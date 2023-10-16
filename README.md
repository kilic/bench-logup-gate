First version of logaritmic derivative lookup [Hab22](https://eprint.iacr.org/2022/1530.pdf) argument is implemented as an halo2 gate. In short, we can observe ~25% gain for batch lookups. This gate is defined with `ConstraintSystem` API and it is not comfortable to work with in practice since the argument requires some specific witness generation procedures. While here we implement logup argument as a gate using frontend API, [scroll/halo2/49](https://github.com/scroll-tech/halo2/pull/49) implements the same argument in more convenient way that replaces existing lookup in constraint system backend. However with this example we also want to show that _precompiles_ such as copy constraints, subset and shuffle arguments may be better implemented in expressive way. So that pluging-in new precompiles into halo2 constraint system backend would be relatively easier.


| Argument  | k    | # of columns | table size | prover time |
| ---       | ---  | ---          | ---        | ---         |
| Subset    | `17` | `8`          | `2^16`     | 8.214s      |
| Logup     | `17` | `8`          | `2^16`     | 6.142s      |
