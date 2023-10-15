use ff::PrimeField;
use halo2::{
    plonk::{
        Advice, Challenge, Column, ConstraintSystem, Constraints, Expression, FirstPhase, Fixed,
        SecondPhase, Selector, TableColumn,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct SubsetConfig<F: PrimeField, const W: usize> {
    pub(crate) w: [Column<Advice>; W],
    pub(crate) t: TableColumn,
    pub(crate) s: Selector,
    pub(crate) _marker: PhantomData<F>,
}

impl<F: PrimeField, const W: usize> SubsetConfig<F, W> {
    pub fn configure(meta: &mut ConstraintSystem<F>, w: &[Column<Advice>; W]) -> Self {
        let t = meta.lookup_table_column();
        let s = meta.complex_selector();

        for w in w.iter() {
            meta.lookup("lookup", |meta| {
                let w = meta.query_advice(*w, Rotation(0));
                let s = meta.query_selector(s);
                vec![(s * w, t)]
            });
        }

        SubsetConfig {
            w: *w,
            t,
            s,
            _marker: PhantomData,
        }
    }
}
