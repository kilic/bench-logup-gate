use std::collections::BTreeMap;

use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    plonk::{Assigned, Error},
};

use crate::{config::LogupConfig, RegionCtx};

#[derive(Clone, Debug)]
pub struct LogupGate<F: PrimeField + Ord, const K: usize> {
    config: LogupConfig<F>,
    bit_size: usize,
    multiplicities: BTreeMap<F, usize>,
    witnesses: Vec<Value<F>>,
}

impl<F: PrimeField + Ord, const K: usize> LogupGate<F, K> {
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
        let alpha: Value<F> = ly.get_challenge(self.config.alpha);

        // find range table
        assert!(K > self.bit_size, "so table can fit in the region");
        let table = (0..1 << self.bit_size).map(F::from).collect::<Vec<_>>();

        // assign table
        ly.assign_region(
            || "assign range table",
            |region| {
                let mut ctx = RegionCtx::new(region);
                for t_i in table.iter() {
                    ctx.fixed(self.config.t, *t_i)?;
                    ctx.next();
                }

                Ok(())
            },
        )?;

        let allignment_offset = std::cmp::max(table.len(), self.witnesses.len());

        // find witness helpers
        let w_helpers = self
            .witnesses
            .iter()
            .chain(std::iter::repeat(&Value::known(F::ZERO)))
            .take(allignment_offset)
            .map(|w| {
                // w_helper_i = 1 / (alpha - w_i)
                let w_helper_i = alpha - w;
                let w_helper_i = w_helper_i.map(|inv| Assigned::Rational(F::ONE, inv));
                w_helper_i
            })
            .collect::<Vec<_>>();

        // find table helpers
        let t_helper = table
            .iter()
            .chain(std::iter::repeat(&F::ZERO))
            .take(allignment_offset)
            .map(|t| {
                // t_helper_i = 1 / (alpha - t_i)
                let t_helper_i = alpha - Value::known(*t);
                let t_helper_i = t_helper_i.map(|inv| Assigned::Rational(F::ONE, inv));
                t_helper_i
            })
            .collect::<Vec<_>>();

        // find multiplicities

        let multiplicities = {
            let domain_size = 1 << K;
            let additional_zeros = domain_size - table.len();

            table
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let m = self.multiplicities.get(&t).unwrap_or(&0);
                    let m = m + if i == 0 { additional_zeros } else { 0 };
                    let m = F::from(m as u64);
                    let m: Value<Assigned<F>> = Value::known(m).into();
                    m
                })
                .chain(std::iter::repeat(Value::known(F::ZERO.into())))
                .take(allignment_offset)
                .collect::<Vec<_>>()
        };

        // assign witness
        ly.assign_region(
            || "assign",
            |region| {
                let mut ctx = RegionCtx::new(region);

                // 1. assign table
                for t_i in table.iter() {
                    ctx.fixed(self.config.t, *t_i)?;
                    ctx.next();
                }
                ctx.zero();

                // 2. assign witnesses
                for w_i in self.witnesses.iter() {
                    ctx.advice(self.config.w, (*w_i).into())?;
                    ctx.enable(self.config.s_lookup)?;
                    ctx.next();
                }
                ctx.zero();

                // assign grand zero sum
                // first acc value is zero
                let mut acc: Value<Assigned<F>> = Value::known(F::ZERO.into());
                ctx.enable(self.config.s_zero)?;
                for (_, ((t, w), m)) in t_helper
                    .iter()
                    .zip(w_helpers.iter())
                    .zip(multiplicities.iter())
                    .enumerate()
                {
                    ctx.enable(self.config.s_acc)?;
                    ctx.advice(self.config.t_helper, *t)?;
                    ctx.advice(self.config.w_helper, *w)?;
                    ctx.advice(self.config.m, *m)?;
                    ctx.advice(self.config.acc, acc)?;

                    acc = acc
                        .zip(*t)
                        .zip(*w)
                        .zip(*m)
                        .map(|(((acc, t), w), m)| acc + m * t - w);

                    ctx.next();
                }

                // prover sanity
                acc.map(|acc| assert_eq!(acc.evaluate(), F::ZERO));

                // last acc value is zero
                ctx.enable(self.config.s_zero)?;

                Ok(())
            },
        )?;

        // assign grand zero sum
        ly.assign_region(
            || "assign grand zero sum",
            |region| {
                let mut ctx = RegionCtx::new(region);
                for w_i in self.witnesses.iter() {
                    ctx.advice(self.config.w, (*w_i).into())?;
                    ctx.enable(self.config.s_lookup)?;
                    ctx.next();
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
