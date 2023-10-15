use std::collections::BTreeMap;

use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    plonk::{Assigned, ConstraintSystem, Error},
};

use crate::{LookupGate, RegionCtx};

use super::config::LogupConfig;

#[derive(Clone, Debug)]
pub struct LogupGate<F: PrimeField + Ord, const W: usize> {
    cfg: LogupConfig<F, W>,
    bit_size: usize,
    multiplicities: BTreeMap<F, usize>,
    witnesses: Vec<[Value<F>; W]>,
}

impl<F: PrimeField + Ord, const W: usize> LookupGate<F, W> for LogupGate<F, W> {
    fn configure(meta: &mut ConstraintSystem<F>, bit_size: usize) -> Self {
        let w = std::iter::repeat_with(|| meta.advice_column())
            .take(W)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let cfg = LogupConfig::configure(meta, &w);

        Self {
            cfg,
            bit_size,
            multiplicities: BTreeMap::new(),
            witnesses: Vec::new(),
        }
    }

    fn lookup(&mut self, value: &[Value<F>; W]) {
        self.witnesses.push(*value);
        value.iter().for_each(|value| {
            value.map(|value| {
                self.multiplicities
                    .entry(value)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);
            });
        });
    }

    fn layout(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        let alpha: Value<F> = ly.get_challenge(self.cfg.alpha);

        let table = (0..1 << self.bit_size).map(F::from).collect::<Vec<_>>();

        // find witness helpers
        let w_helper: Vec<[Value<Assigned<F>>; W]> = self
            .witnesses
            .iter()
            .enumerate()
            .map(|(_i, w)| {
                w.iter()
                    .map(|w| {
                        // w_helper_i = 1 / (alpha - w_i)
                        (alpha - w).map(|inv| Assigned::Rational(F::ONE, inv))
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // find table helpers
        let t_helper = table
            .iter()
            .enumerate()
            // t_helper_i = 1 / (alpha - t_i)
            .map(|(_i, t)| (alpha - Value::known(*t)).map(|inv| Assigned::Rational(F::ONE, inv)))
            .collect::<Vec<_>>();

        // find multiplicities
        let multiplicities = table
            .iter()
            .enumerate()
            .map(|(_i, t)| {
                let m: F = (*self.multiplicities.get(t).unwrap_or(&0) as u64).into();
                let m: Value<Assigned<F>> = Value::known(m).into();
                m
            })
            .collect::<Vec<_>>();

        ly.assign_region(
            || "assign",
            |region| {
                let mut ctx = RegionCtx::new(region);

                let acc_off = std::cmp::max(self.witnesses.len(), table.len());

                let multiplicities = multiplicities
                    .iter()
                    .map(Some)
                    .chain(std::iter::repeat(None))
                    .take(acc_off);
                let table = table
                    .iter()
                    .zip(t_helper.iter())
                    .map(Some)
                    .chain(std::iter::repeat(None))
                    .take(acc_off);
                let witneses = self
                    .witnesses
                    .iter()
                    .zip(w_helper.iter())
                    .map(Some)
                    .chain(std::iter::repeat(None))
                    .take(acc_off);

                // init acc to zero
                let mut acc: Value<Assigned<F>> = Value::known(F::ZERO).into();
                ctx.enable(self.cfg.s_zero)?;

                for (_i, ((t, w), m)) in table.zip(witneses).zip(multiplicities).enumerate() {
                    ctx.enable(self.cfg.s_acc)?;
                    ctx.advice(self.cfg.acc, acc)?;

                    match (t, m) {
                        (Some((t, h)), Some(m)) => {
                            ctx.enable(self.cfg.s_table)?;

                            ctx.fixed(self.cfg.t, *t)?;
                            ctx.advice(self.cfg.t_helper, *h)?;
                            ctx.advice(self.cfg.m, *m)?;

                            acc = acc + *h * m;
                        }
                        (None, None) => {
                            ctx.empty(self.cfg.t_helper.into())?;
                            ctx.empty(self.cfg.m.into())?;
                        }
                        _ => unreachable!(),
                    }

                    match w {
                        Some((w, h)) => {
                            for (i, (w, h)) in w.iter().zip(h.iter()).enumerate() {
                                let w: Value<Assigned<F>> = (*w).into();
                                ctx.enable(self.cfg.s_witness)?;

                                ctx.advice(self.cfg.w[i], w)?;
                                ctx.advice(self.cfg.w_helper[i], *h)?;

                                acc = acc - h;
                            }
                        }
                        _ => {
                            for i in 0..W {
                                ctx.empty(self.cfg.w[i].into())?;
                                ctx.empty(self.cfg.w_helper[i].into())?;
                            }
                        }
                    }
                    ctx.next();
                }

                ctx.advice(self.cfg.acc, acc)?;
                ctx.enable(self.cfg.s_zero)?;
                acc.map(|acc| assert_eq!(acc.evaluate(), F::ZERO));

                Ok(())
            },
        )?;

        Ok(())
    }
}
