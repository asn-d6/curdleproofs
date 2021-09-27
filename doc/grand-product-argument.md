# GrandProduct Argument

The *GrandProduct argument* proves the relation:

\\[
R_{gprod} =
\\left\\{
\\begin{array} {l l|l}
	(B, p); & (\\bm{b}, \\bm{r}\_B)
	&
	B =  \bm{b} \\times \bm{g} + \bm{r}\_B \\times \bm{h}  \\\\
	& & p = \\prod_{i=1}^{\ell} b_i
\\end{array}
\\right\\}
\\\]

The construction makes use of a discrete-logarithm inner product argument as a subprotocol.

## Protocol

A formal description of the *gprod* argument is provided in the figure below:

<center>
<img width="80%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/gprod_prover.png"></img>
</center>

## Informal Overview

The prover will take as input the $B, p$ and aims to prove knowledge of $\bm{b}$ such that:
- $B = \bm{b} \times \bm{g}$ is a commitment to $\bm{b}$
- $p = \prod_{i=1}^{\ell} b_i$ is the grandproduct of $\bm{b}$

On a high level we aim to express this relation as an inner product argument.

Doing this consists of the following steps:
- We *separate* the grandproduct into multiple single product equations;
- We *compress* all our equations into a polynomial;
- We *rearrange* the polynomial into an inner product equation;
- We *compile* the proving system by obtaining commitments to the inputs to the inner product equation;

See the figure below for how the grandproduct argument is compiled into an inner product argument.

<center>
<img width="60%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/gprod_overview.png">
</center>

#### Separate

The product $p = \prod_{i=1}^{\ell} b_i$ consists of $\ell - 1$ multiplications.
Initially we *separate* these multiplications into $\ell + 1$ separate multiplication checks
\\[
c_{1} = 1 \ \land \ c_{i+1} = b_{i} c_i, \ i \in [1, \ell) \ \land \ p = b_{\ell} c_{\ell}
\\\]
that iteratively define a vector $\bm{c}$.  The final check enforces that $p = \prod_{i=1}^{\ell} b_i$ is the grandproduct of $\bm{b}$.

#### Compress

To ensure that each of our multiplication checks hold we compress them into a single polynomial equation
\\[
0  = (  1 - c_1 ) + ( b_1 c_1 - c_2) X + ( b_2 c_2 - c_3) X^2 + \ldots + (b_{\ell-1} c_{\ell - 1} - c_\ell ) X^{\ell - 1} + (b_{\ell} c_{\ell} - p ) X^{\ell} \\
\\\]
or equivalently
\\[
0  = (1 - c_1 ) + \sum_{i = 1}^{\ell - 1} (  b_{i} c_i - c_{i+1})X^i + (b_{\ell} c_{\ell} - p ) X^{\ell}
\\\]
in the indeterminate $X$ where each coefficient is checking a single constraint.

#### Rearrange

Our eventual goal is to express the equation $(1)$ below as an inner product equation such that we can run an inner product argument.
We thus rearrange the $\bm{c}$ terms and see that:

\\[
p X^{\ell} - 1 = c_1 ( X b_1 - 1 ) + c_2 ( X^2 b_2 - X ) + \ldots + c_{\ell - 1} ( X^{\ell - 1} b_{\ell-1} - X^{\ell - 2} ) + c_{\ell} (  X^{\ell} b_{\ell} - X^{\ell - 1})
\\\]
or equivalently

\\[
p X^{\ell} - 1    = \sum_{i = 1}^{\ell } c_i (X^i b_{i} -  X^{i - 1}  )
\\\]

#### Compile
By the Schwartz-Zippel lemma our inner product equation holds with overwhelming probability if at a random point $\beta$

\\begin{equation}
	p \beta^{\ell} - 1    = \sum_{i = 1}^{\ell } c_i (\beta^i b_{i} -  \beta^{i - 1}  )
\\end{equation}

Equivalently
\\\[
z = \bm{c} \times \bm{d}
\\\]

where

\\[
z = p \\beta^{\\ell} - 1 \\ \\land \\
d_i =  ( \\beta^i b_{i} - \\beta^{i - 1}  ), \\ i \\in [1, \\ell]
\\]
We thus require a commitment to $\bm{c}$ and $\bm{d}$.

Initially the prover provides a commitment $C = \bm{c} \times \bm{g}$ to
\\[
\bm{c} = (1,b_1,b_1 b_2, b_1b_2 b_3,  \ldots, b_1 \ldots b_{\ell-1} )
\\]
The commitment $C$ is hashed to get $\beta$.
We now require a commitment $D$ to the vector $\bm{d}$.  We have a commitment $B = \bm{b} \times \bm{g}$ to $\bm{b}$.
Recall that
\\[
\bm{v} \times \bm{w} = (a_1 v_1, \ldots, a_{\ell} v_{\ell}) \times (a_1^{-1} w_1, \ldots, a_{\ell}^{-1} w_{\ell})
\\]
for all invertible $\bm{a}$.
Thus we can view $B$ as being a commitment to a  rescaled vector $\bm{b}'$
under an appropriately rescaled commitment key $\bm{g}'$

\\[
\\begin{align*}
    \bm{b}' & = ( \beta^1 b_{1}, \ldots, \beta^{\ell } b_{\ell})   \\\\
	\bm{g}' & =  ( \beta^{-1} g_1, \ldots, \beta^{-(\ell)} g_{\ell}) \\\\
	B &= \bm{b}' \times \bm{g}'
\\end{align*}
\\]

Now
\\[
\bm{d} = \bm{b}' - (1, \beta, \ldots, \beta^{\ell - 1})
\\]
Hence the prover and verifier compute
\\[
D = B  - \sum_{i = 1}^{\ell } \beta^{i - 1} g_i'
\\]
such that $D = \bm{d} \times \bm{g}'$ is a commitment to $\bm{d}$ under $\bm{g}'$.



To finish, the prover provides a discrete log inner product argument, the relation for which is formally defined below, attesting to the existence of $\bm{c}$ and $\bm{d}$ such that
\\[
C = \bm{c} \times \bm{g}, \ D = \bm{d} \times \bm{g}', \ p \beta^{\ell} - 1 = \bm{c} \times \bm{d}
\\]
By design there exists a non-trivial relation between $\bm{g}$ and $\bm{g}'$.
The full construction has some additional masking values that are included to ensure zero-knowledge.   For simplicity we have ignored these terms in this overview.

## Full Zero Knowledge Grand Product Construction

Here we describe the additional steps that we have added compared to the informal overview above to achieve zero-knowledge.

##### Step 1:

In the first step the prover and verifier both hash the instance to get a random value $\alpha$.
This allows the prover to mask $\bm{r}_B$ in the next step even when $\bm{r}_B = \bm{0}$.
There are no secrets in this step.  The verifier parses all inputs to check that they are group or field elements.

##### Step 2

In the second step the prover computes a commitment $C$ to $\bm{c}$.  The vector $\bm{c}$ depends on $\bm{b}$ and thus must be kept private.
Thus the prover chooses a random blinding vector $\bm{r}\_{C} \in \bm{F}^{n\_{bl}}$.  This vector $\bm{r}_C$ is included in the inner product argument in the final step, and thus the prover provides a field element $r_p = ( \bm{r}_B + \alpha \bm{1}) \times \bm{r}_C$ that cancels out the blinders contributions to the inner product.  See here that the $\alpha  ( \bm{1} \times \bm{r}_C)$ component ensures that $r_p$ is satistically blinded provided that $|\bm{r}_C| \geq 2$.

##### Step 3

In the third step the prover and verifier compute $\bm{h}' = \beta^{ -(\ell + 1)} \bm{h}$ as the rescaled part of the commitment key that is used for blinding commitments.  The prover additionally computes
randomness $\bm{r}_D = \beta^{\ell + 1} (\bm{r}_B + \alpha \bm{1})$ such that $D = \bm{d} \times \bm{g}' + \bm{r}_D \times \bm{h}'$ is a commitment to $\bm{d}$.  Here $\beta^{\ell + 1}$ does not overlap with the $(\beta, \beta^2, \ldots, \beta^{\ell})$ values that are used to rescale $\bm{b}'$.

##### Step 4

In the fourth and final step the prover and verifier compute the commitment key $\bm{G} = (\bm{g} \ || \ \bm{h})$ so that they can view $\bm{C}$ as a commitment to the extended vector $(\bm{c} \ || \ \bm{r}_C)$.  They do the same for $\bm{G}'$ such that $\bm{D}$ is a commitment to the extended vector $(\bm{d} \ || \ \bm{r}_D)$.
They compute $z = p \beta^{\ell} + r_p \beta^{\ell + 1} - 1$ as the inner product of the extended vectors $z = (\bm{c} \ || \ \bm{r}_C) \times (\bm{d} \ || \ \bm{r}_D)$.  See that $r_p \beta^{\ell + 1} = \bm{r}_C \times \bm{r}_D$.  There are no secrets involved in this step.

