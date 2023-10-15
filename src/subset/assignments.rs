use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error},
};

use crate::{LookupGate, RegionCtx};

use super::config::SubsetConfig;

#[derive(Clone, Debug)]
pub struct SubsetGate<F: PrimeField + Ord, const W: usize> {
    cfg: SubsetConfig<F, W>,
    bit_size: usize,
    witnesses: Vec<[Value<F>; W]>,
}

impl<F: PrimeField + Ord, const W: usize> LookupGate<F, W> for SubsetGate<F, W> {
    fn configure(meta: &mut ConstraintSystem<F>, bit_size: usize) -> Self {
        let w = std::iter::repeat_with(|| meta.advice_column())
            .take(W)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let cfg = SubsetConfig::configure(meta, &w);

        Self {
            cfg,
            bit_size,
            witnesses: Vec::new(),
        }
    }

    fn lookup(&mut self, value: &[Value<F>; W]) {
        self.witnesses.push(*value);
    }

    fn layout(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        // layout table
        ly.assign_table(
            || "",
            |mut table| {
                let table_values: Vec<F> = (0..1 << self.bit_size).map(|e| F::from(e)).collect();
                for (offset, value) in table_values.iter().enumerate() {
                    table.assign_cell(
                        || "table value",
                        self.cfg.t,
                        offset,
                        || Value::known(*value),
                    )?;
                }
                Ok(())
            },
        )?;

        // latout witnesses

        ly.assign_region(
            || "assign",
            |region| {
                let mut ctx = RegionCtx::new(region);

                for w in self.witnesses.iter() {
                    for (w, col) in w.iter().zip(self.cfg.w) {
                        ctx.advice(col, w.map(|w| w.into()))?;
                    }
                    ctx.enable(self.cfg.s)?;
                    ctx.next();
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
