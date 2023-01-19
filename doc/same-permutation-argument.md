# Same Permutation Argument

The *Same Permutation argument* proves the relation:

\\[
R_{sameperm} =
\\left\\{
\\begin{array}{l l|l}
	(A, M, \bm{a}) ;& (  \sigma(), \bm{r}_A, \bm{r}_M)
	&
	A =  \sigma( \bm{a} ) \times \bm{g} + \bm{r}_A \times \bm{h} \\\\
	& &   M =  \sigma(1, \ldots, \ell) \times \bm{g} + \bm{r}_M \times \bm{h}
\\end{array}
\\right\\}
\\\]

The following figure provides a high-level overview of the Same Permutation argument construction.

<center>
<img width="50%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/same_perm_overview.png"></img>
</center>

The construction uses a [Grand Product argument](crate::grand_product_argument) as a subargument.

## Protocol

A formal description of the *sameperm* argument is provided in the figure below:

<center>
<img width="80%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/same_perm.png"></img>
</center>

## Neff's Trick

The argument takes advantage of an observation (first applied in the proof context by [Neff](https://web.cs.ucdavis.edu/~franklin/ecs228/2013/neff_2001.pdf))
that two polynomials are equal if and only if their  roots  are the same up to permutation.
In other words
\\[
\sigma(\bm{a}) = \bm{c} \quad \Leftrightarrow \quad (a_1 + Y) (a_2 + Y) \cdots (a_{\ell} + Y ) = (c_1 + Y)(c_2 + Y) \cdots (c_\ell + Y)
\\]
as polynomials of  $Y$.
We can additionally bind $\bm{a}$ and $\bm{c}$ to a specific permutation $\sigma()$ through including an additional indeterminate $X$.
Indeed whenever the polynomial equation
\\[
(a_1 + X +  Y) (a_2 + 2X +  Y) \cdots (a_{\ell} + \ell X +  Y )  =  (c_1 + m_1 X + Y)(c_2 + m_2 X + Y) \cdots (c_\ell + m_{\ell} X +  Y)
\\] holds
we have that there exists $\sigma()$ such that
\\[
\sigma(a_1 + X, a_2 + 2X, \ldots, a_\ell + \ell X)  =   (c_1 + m_1 X, c_2 + m_2 X, \ldots, c_\ell + m_\ell X) \\
\\]
This implies that $\sigma( \bm{a}) = \bm{c}$ and $\sigma(1, \ldots, \ell) = \bm{m}$.

## Informal Overview

The prover will take as input the $A, M, \bm{a}$ and aims to prove knowledge of $ \sigma() $ such that:
- $A = \sigma(\bm{a}) \times \bm{g}$ is a commitment to $\sigma( \bm{a} )$
- $M = \sigma(1,2, \ldots, \ell) \times \bm{g}$ is a commitment to $\sigma()$

The verifier wishes to check that $A$ and $M$ are commitments to $\bm{c}$ and $\bm{m}$ respectively such that

\\[
(a_1 + X +  Y) (a_2 + 2X +  Y) \cdots (a_{\ell} + \ell X +  Y )  =  (c_1 + m_1 X + Y)(c_2 + m_2 X + Y) \cdots (c_\ell + m_{\ell} X +  Y)
\\]

Initially all the public inputs $(A, M, \bm{a})$ are hashed to get challenges $\alpha, \beta$ and we must show that:

\\[
(a_1 + \alpha +  \beta) (a_2 + 2 \alpha +  \beta) \cdots (a_{\ell} + \ell \alpha +  \beta ) =
(c_1 + m_1 \alpha + \beta)(c_2 +  m_2 \alpha + \beta) \cdots (c_\ell + m_{\ell} \alpha +  \beta)
\\]
By the Schwartz-Zippel Lemma this implies that the polynomial expression holds except with negligible probability.

Next the prover and verifier both compute values
$p = \prod_{i = 1}^{\ell} (a_i + i \alpha + \beta)$ and $B = A + \alpha M + \bm{\beta} \times \bm{g}$ where $\bm{\beta} = (\beta, \beta, \ldots, \beta)$.

By the homomorphic properties of the Pedersen commitment we see that $B$ is thus a commitment to 
\\[ \bm{b} = \bm{c} + \alpha \bm{m} + \beta \bm{1} = ( c_1 + m_1 \alpha + \beta, c_2 + m_2  \alpha + \beta , \ldots, c_\ell + m_\ell \alpha + \beta  )\\]
Here $\bm{1} = (1, \ldots, 1)$ is the length $\ell$ vector where every entry equals $1$.
Then the prover uses a grand-product argument to describe knowledge of $\bm{b}$ such that $B$ is a commitment to $\bm{b}$ and $p$ is a grandproduct of $\bm{b}$.
This implies that
\\[
 \prod_{i = 1}^{\ell} (a_i + i \alpha + \beta) =  \prod_{i = 1}^{\ell} ( c_i + m_i \alpha + \beta)
\\]
and hence that $\bm{m} = \sigma(1, \ldots, \ell)$, $\bm{c} = \sigma(\bm{a})$ for some $\sigma()$.

Note that the full same-permutation protocol has some additional masking values that are included to ensure zero-knowledge.   For simplicity we have ignored these terms in this overview.

