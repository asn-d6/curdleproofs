# Curdleproofs optimizations

Curdleproofs is optimized for quick verification. This section goes into more details on the optimizations deployed.

## MSM Accumulator

Throughout the protocol there are checks of the form
\\[C  \\stackrel{?}{=}  \\bm{x} \\times ( \\bm{g} \\ || \\ \\bm{h} \\ || \\ G_T \\ || \\ G_U \\ || \\ H \\ || \\ \\bm{R} \\ || \\ \\bm{S} \\ || \\ \\bm{T} \\ || \\ \\bm{U}) \\]
These checks form the bottleneck of the verifiers computation and we can save significant amounts of work by accumulating these checks into a single multiscalar multiplication that is checked at the end of the protocol.

We implement the optimization in the [`crate::msm_accumulator`] crate.

## IPA Verification Scalars

We use an optimization from [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) to reduce the verifier overhead in
inner product arguments that is also used in the [Dalek
implementation](https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html). We will demonstrate the
optimization for the $SameMsm$ argument, but same reasoning applies for the $DLinner$ argument as well.

The verifier computes only three checks in the entire $SameMsm$ argument: namely in Step 3 it checks that $A = x G_1$,
$Z_T = x T_1$, and $Z_U = x U_1$.  This means that although the prover needs to compute the intermediate vectors
$\bm{G}, \bm{T}, \bm{U}$ at each step in order to compute the $\pi_j$ values, the verifier does not and it can compute
the final $A, Z_T, Z_U, G_1, T_1, U_1$ directly from the initial $A, Z_T, Z_U, \bm{G}, \bm{T}, \bm{U}$ and the $B_A,
B_T, B_U, \bm{\gamma}$ values.

Using a simple example where the starting $|\bm{G}| = 8$, we see that $\bm{G}$ gets changed as follows:
\\[
\\begin{array}{c c c c c c c c c c c c c c c c c}
 & \\bm{G} = & (G_1'     & || &  G_2' & ||  & G_3'  & ||  & G_4'  & ||  & G_5'  & ||  & G_6'  & ||  & G_7'  & ||   & G_8') \\\\
 & \\bm{G} = & ( G_1'  & + &  \\gamma_1 G_5'  & ||  & G_2' &  + & \\gamma_1 G_6'  & ||  & G_3' & + &  \\gamma_1 G_7'  & ||  & G_4' &   + & \\gamma_1 G_8' )
	\\\\
 & \\bm{G} = & ( G_1'  & + &   \\gamma_2  G_3'  & +  & \\gamma_1 G_5'&  + & \\gamma_1 \\gamma_2 G_7'  & ||  & G_2' & + &  \\gamma_2 G_4'  & +  & \\gamma_1 G_6' &   + & \\gamma_1 \\gamma_2 G_8')
	\\\\
 & \\bm{G} = & ( G_1'  & + &   \\gamma_3  G_2'  & +  & \\gamma_2  G_3' &  + &  \\gamma_2 \\gamma_3 G_4'  & +  & \\gamma_1 G_5' & + &   \\gamma_1 \\gamma_3 G_6'  & +  &  \\gamma_1 \\gamma_2 G_7' &   + & \\gamma_1 \\gamma_2 \\gamma_3 G_8')
\\end{array}
\\]
such that the final $G_1$ value is equal to
\\[
( 1, \\ \\gamma_3, \\ \\gamma_2, \\ \\gamma_{2} \\gamma_3,  \\ \\gamma_1, \\ \\gamma_1 \\gamma_3, \\ \\gamma_1 \\gamma_2, \\ \\gamma_1 \\gamma_2 \\gamma_3 ) \\times \\bm{G}
\\]
If we set $\\bm{\\delta} = (\\gamma_m, \\ldots, \\gamma_1)$ to be the reverse of $\\bm{\\gamma}$ then we see a useful structure
\\[
G_1 = ( 1, \\ \\delta_1, \\ \\delta_2, \\ \\delta_{1} \\delta_2,  \\ \\delta_3, \\ \\delta_1 \\delta_3, \\ \\delta_2 \\delta_3, \\ \\delta_1 \\delta_2 \\delta_3 ) \\times \\bm{G}
\\]
namely that
$G_1 = \\bm{s} \\times \\bm{G}$ where
$s_i = \\sum_{ j = 1 }^{m} \\delta_j^{b_{i,j}}$ for $b_{i,j}$ such that $i = \\sum_{j = 1}^m b_{i,j} 2^j$ is the binary decomposition of $i$.

## Grandproduct Verifier Optimizations

The non-optimized grandproduct verifier is required to compute a vector $\\bm{G}' = \\bm{u} \\circ \\bm{G}$
for some public vector $\\bm{u}$.
Then $\\bm{G}'$ is used as input to the $DLInner$ common reference string.
Computing $\\bm{G}' = \\bm{u} \\circ \\bm{G}$ would cost $n$ scalar multiplications that cannot be accumulated efficiently.
However, when we look into how the vector $\\bm{G}'$ is used in $DLInner$, it is used only once during
\\[
AccumulateCheck( \\bm{\\gamma} \\times \\bm{L}\_{D} +  (B\_D + \\alpha D) + \\bm{\\gamma}^{-1} \\times \\bm{R}\_{D}  \\stackrel{?}{=} d \\bm{s}' \\times \\bm{G}' )
\\]
This check is equivalent to accumulating the check
\\[
AccumulateCheck( \\bm{\\gamma} \\times \\bm{L}\_{D} +  (B\_D + \\alpha D) + \\bm{\\gamma}^{-1} \\times \\bm{R}\_{D}  \\stackrel{?}{=} (d \\bm{s} \\circ \\bm{u} ) \\times \\bm{G} )
\\]
We thus edit the $DLInner$ verifier to only take the original generators as input in $crs_{DLInner} = (\\bm{G}, H)$, however to take $\\bm{u}$ one of the public inputs $\\phi_{DLInner} = (C, D, z, \\bm{u})$.
The accumulated check can then be run efficiently.

A second optimization we run is that the non-optimized grandproduct verifier is required to compute a group element
\\[
D \\gets B  -  (1, \\beta, \\ldots, \\beta^{\\ell - 1} ) \\times \\bm{g}' + \\alpha \\beta^{\\ell + 1}  \\bm{1}  \\times \\bm{h}'
\\]
for 
\\[
\\bm{g}' \\gets ( (\\beta^{-1} g_2 , \\beta^{-2} g_3, \\ldots, \\beta^{-(\\ell-1)} g_{\\ell} ) \\ || \\ \\beta^{-\\ell} g_1 ) \\ \\land \\ \\bm{h}' \\gets \\beta^{-(\\ell + 1)} \\bm{h}
\\]
Expanding we see that
\\[
\\begin{align*}
(1, \\beta, \\ldots, \\beta^{\\ell - 1} ) \\times \\bm{g}' & = (1, \\beta, \\ldots, \\beta^{\\ell - 1} ) \\times ( (\\beta^{-1} g_2 , \\beta^{-2} g_3, \\ldots, \\beta^{-(\\ell-1)} g_{\\ell} ) \\ || \\ \\beta^{-\\ell} g_1 ) \\\\
& = ( (\\beta^{-1} g_2 , \\beta^{-1} g_3, \\ldots, \\beta^{-1} g_{\\ell} ) \\ || \\ \\beta^{-1} g_1 )  \\\\
& = \\beta^{-1} \\sum_{i=1}^{\\ell} g_{i}
\\end{align*}
\\]
Similarly
\\[
\\begin{align*}
	\\alpha \\beta^{\\ell + 1}  \\bm{1}  \\times \\bm{h}' & = 	\\alpha \\beta^{\\ell + 1}  \\bm{1}  \\times \\beta^{-(\\ell + 1)} \\bm{h} \\\\
	& = \\alpha \\sum_{i = 1}^{n_{bl}} h_i
\\end{align*}
\\]
If we store $g_{\\mathsf{sum}} =  \\sum_{i=1}^{\\ell} g_{i}$ and $h_{\\mathsf{sum}} =  \\sum_{i=1}^{\\ell} h_{i}$ in the CRS then we can compute
\\[
D \\gets B  - \\beta^{-1} g_{\\mathsf{sum}} + \\alpha h_{\\mathsf{sum}}
\\]
in just $2$ scalar multiplications.

