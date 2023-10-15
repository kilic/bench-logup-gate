use ff::PrimeField;
use halo2::{
    plonk::{
        Advice, Challenge, Column, ConstraintSystem, Constraints, Expression, FirstPhase, Fixed,
        SecondPhase, Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

// TODO:
// * batch lookup

#[derive(Clone, Debug)]
pub struct LogupConfig<F: PrimeField> {
    pub(crate) w: Column<Advice>,
    pub(crate) t: Column<Fixed>,
    pub(crate) t_helper: Column<Advice>,
    pub(crate) w_helper: Column<Advice>,
    pub(crate) m: Column<Advice>,
    pub(crate) acc: Column<Advice>,
    pub(crate) alpha: Challenge,

    pub(crate) s_zero: Selector,
    pub(crate) s_acc: Selector,

    pub(crate) s_witness: Selector,
    pub(crate) s_table: Selector,

    pub(crate) marker: PhantomData<F>,
}

impl<F: PrimeField> LogupConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, w: Column<Advice>) -> Self {
        let t = meta.fixed_column();
        let m = meta.advice_column_in(SecondPhase);
        let t_helper = meta.advice_column_in(SecondPhase);
        let w_helper = meta.advice_column_in(SecondPhase);
        let acc = meta.advice_column_in(SecondPhase);

        let alpha = meta.challenge_usable_after(FirstPhase);

        let s_zero = meta.selector();
        let s_acc = meta.selector();

        let s_table = meta.complex_selector();
        let s_witness = meta.complex_selector();

        // t_helper(X) * (alpha - t(X)) = 1
        meta.create_gate("t-helper", |meta| {
            let t = meta.query_fixed(t, Rotation(0));
            let t_helper = meta.query_advice(t_helper, Rotation(0));
            let alpha = meta.query_challenge(alpha);
            let identity = t_helper * (alpha - t) - Expression::Constant(F::ONE);

            let selector = meta.query_selector(s_table);
            Constraints::with_selector(selector, std::iter::once(identity))
        });

        // w_helper(X) * (alpha - w(X)) = 1
        meta.create_gate("w-helper", |meta| {
            let w = meta.query_advice(w, Rotation(0));
            let w_helper = meta.query_advice(w_helper, Rotation(0));
            let alpha = meta.query_challenge(alpha);
            let identity = w_helper * (alpha - w) - Expression::Constant(F::ONE);

            let selector = meta.query_selector(s_witness);
            Constraints::with_selector(selector, std::iter::once(identity))
        });

        // sum(m(x) * t_helper(x) - w_helper(x)) == 0
        meta.create_gate("grand sum", |meta| {
            let m = meta.query_advice(m, Rotation(0));
            let s_table = meta.query_selector(s_table);
            let s_witness = meta.query_selector(s_witness);

            let contrib = {
                let w_helper = meta.query_advice(w_helper, Rotation(0));
                let t_helper = meta.query_advice(t_helper, Rotation(0));
                // with the hope that deggree stays at 3
                s_table * m * t_helper - s_witness * w_helper
            };
            let acc_next = meta.query_advice(acc, Rotation(1));
            let acc = meta.query_advice(acc, Rotation(0));
            let identity = contrib + acc - acc_next;

            let selector = meta.query_selector(s_acc);
            Constraints::with_selector(selector, std::iter::once(identity))
        });

        // zero sum check
        meta.create_gate("zero acc", |meta| {
            let acc = meta.query_advice(acc, Rotation(0));
            let identity = acc - Expression::Constant(F::ZERO);
            let selector = meta.query_selector(s_zero);
            Constraints::with_selector(selector, std::iter::once(identity))
        });

        Self {
            w,
            t,
            t_helper,
            w_helper,
            m,
            acc,
            alpha,

            s_acc,
            s_zero,

            s_table,
            s_witness,

            marker: PhantomData,
        }
    }
}
