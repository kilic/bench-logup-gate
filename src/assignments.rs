use std::collections::BTreeMap;

use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    plonk::{Assigned, ConstraintSystem, Error},
};

use crate::{config::LogupConfig, RegionCtx};

fn _debug_assigned<F: PrimeField>(desc: &str, e: &[Value<Assigned<F>>]) {
    e.iter().enumerate().for_each(|(i, e)| {
        e.map(|e| println!("{desc}_{i}: {:#?}", e.evaluate()));
    });
}

#[derive(Clone, Debug)]
pub struct LogupGate<F: PrimeField + Ord, const K: usize> {
    pub cfg: LogupConfig<F>,
    bit_size: usize,
    multiplicities: BTreeMap<F, usize>,
    witnesses: Vec<Value<F>>,
}

impl<F: PrimeField + Ord, const K: usize> LogupGate<F, K> {
    pub fn configure(meta: &mut ConstraintSystem<F>, bit_size: usize) -> Self {
        let w = meta.advice_column();
        let cfg = LogupConfig::configure(meta, w);
        Self {
            cfg,
            bit_size,
            multiplicities: BTreeMap::new(),
            witnesses: Vec::new(),
        }
    }

    pub fn lookup(&mut self, value: Value<F>) {
        self.witnesses.push(value);
        value.map(|value| {
            self.multiplicities
                .entry(value)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        });
    }

    pub fn layout(
        &self,
        ly: &mut impl Layouter<F>,
        // ) -> Result<Vec<Value<Assigned<F>>>, Error> {
    ) -> Result<(), Error> {
        let alpha: Value<F> = ly.get_challenge(self.cfg.alpha);

        // find range table
        assert!(K > self.bit_size, "so table can fit in the region");
        let table = (0..1 << self.bit_size).map(F::from).collect::<Vec<_>>();

        // find witness helpers
        let w_helper = self
            .witnesses
            .iter()
            .enumerate()
            // w_helper_i = 1 / (alpha - w_i)
            .map(|(_i, w)| (alpha - w).map(|inv| Assigned::Rational(F::ONE, inv)))
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
                            let w: Value<Assigned<F>> = (*w).into();
                            ctx.enable(self.cfg.s_witness)?;

                            ctx.advice(self.cfg.w, w)?;
                            ctx.advice(self.cfg.w_helper, *h)?;

                            acc = acc - h;
                        }
                        _ => {
                            ctx.empty(self.cfg.w.into())?;
                            ctx.empty(self.cfg.w_helper.into())?;
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
