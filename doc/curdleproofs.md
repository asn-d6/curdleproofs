# The Curdleproofs shuffle argument

The aim of Curdleproofs is to build a shuffle argument of group elements.
More precisely, given a public set of group elements
$\\bm{R} =  ( R_1 , \\ldots,   R_\\ell  )$ and
$\\bm{S} =  (   S_1 , \\ldots, S_{\\ell}  )$
a shuffler computes a second set of group elements
$\\bm{T} =  ( T_1, \\ldots,  T_\\ell  )$ and
$\\bm{U} =  (  U_1, \\ldots, U_{\\ell} )$
and proves in zero knowledge that there exists a permutation
\\[
\\sigma:  [1, \\ell] \\mapsto [1,\\ell]
\\]
and a field element $k \\in F$
such that for all $1 \\leq i \\leq \\ell$
\\[
T_{i} = k R_{\\sigma(i)}  \\ \\land \\ U_i = k  S_{\\sigma(i)} \\enspace .
\\]
The permutation $\\sigma()$ is committed to in $M \\in G$ under some randomness $\\bm{r}_M \\in F^{n\_{bl}}$.

Note that by the $\\ell$-$ddh$ assumption it is difficult to distinguish the randomised ciphertexts from truly random values.

In other words we define a zero-knowledge proof for the relation

\\[
R_{shuffle} =
\\left\\{
\\begin{array}{l l|l}
(\\bm{R}, \\bm{S}, \\bm{T}, \\bm{U}, M);
&
\\sigma
&
\\bm{T} =  \\sigma ( k \\bm{R} )
\\\\
 &  k \\in F & \\bm{U} =  \\sigma ( k \\bm{S} ) \\\\
 & \\bm{r}\_M\\in F^{n\_{bl}} & M = \\sigma(1, \\ldots, \\ell) \\times \\bm{g} + \\bm{r}\_M \\times \\bm{h}
\\end{array}
\\right\\}
\\]

## Subarguments

Curdleproofs uses multiple subarguments to achieve its goals. A graphical depiction of the proof's flow can be seen
below.

<center>
<img width="60%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/curdleproofs_overview.png"></img>
</center>

## Protocol

A formal description of the *curdleproofs* argument is provided in the figure below:

<center>
<img width="100%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/curdleproofs_prover.png"></img>
</center>

## Protocol Informal Overview

Let $\ell>1$. The prover will take as input the $\bm{R}, \bm{S}, \bm{T}, \bm{U}, M$ and aims to prove knowledge of $\sigma(), k$ such that:
- $M = \sigma(1,2, \ldots, \ell) \times \bm{g}$ is a commitment to $\sigma()$
- $\bm{T} = \sigma(k \bm{R}) $ is a randomised permutation of $\bm{R}$
- $\bm{U}= \sigma(k \bm{S}) $ is a randomised permutation of $\bm{S}$

 Initially all the public inputs are hashed to get a vector $\bm{a}$ of challenges.  Then the prover computes  values $A = \sigma(\bm{a}) \times \bm{g}$,
 $T = \bm{a} \times k\bm{R}$, and $U = \bm{a} \times k \bm{S}$ which it sends to the verifier.
  As part of our full construction we require zero-knowledge algorithms for proving and verifying three additional relations: a same permutation relation, a same scalar relation, and a same multiscalar relation.

The prover runs the following arguments:
- [SamePerm argument](crate::same_permutation_argument) to demonstrate that $A$ is a commitment to $\sigma(\bm{a})$ for $\sigma()$ the permutation committed to with $M$.
- [SameMultiScalar argument](crate::same_multiscalar_argument) to show the existence of some $\bm{x}$ such that $A = \bm{x} \times \bm{g}$, $T = \bm{x} \times \bm{T}$ and $U = \bm{x} \times \bm{U}$.  Where $A = \sigma( \bm{a}) \times \bm{g} =  \bm{x} \times \bm{g}$ this gives us that
  $T = \sigma(\bm{a}) \times \bm{T}$ and $U = \sigma(\bm{a}) \times \bm{U}$.
- [SameScalar argument](crate::same_scalar_argument) to show the existence of $k$ such that $T = k (\bm{a} \times \bm{R})$ and $U = k (\bm{a} \times \bm{S})$.

Together this means that

$T = k (\bm{a} \times \bm{R}) = \sigma(\bm{a}) \times \bm{T}$ and $U = \sigma(\bm{a}) \times \bm{U} = k (\bm{a} \times \bm{S})$

Where $\bm{a}$ is random this means that $k R_{\sigma(i)} = T_i $ for all $i$ except with negligible probability.

Note that the full protocol has some additional masking values that are included to ensure zero-knowledge.   For simplicity we have ignored these terms in this overview.

## Full Zero Knowledge Construction

Here we describe the additional steps required to achieve zero-knowledge.

##### Step 1
In the first step the prover and verifier both hash the instance to get a random vector of field elements $\bm{a} \in F^{\ell}$.
There are no secrets involved in this step.
The verifier parses all inputs to check that they are group or field elements.

#####  Step 2
In the second step the prover computes a commitment $A$ to the permuted $\sigma(\bm{a})$.
The vector $\sigma(\bm{a})$ is private because it reveals information about the secret permutation $\sigma()$.
The prover therefore chooses a random blinding vector $\bm{r}\_{A} \in \bm{F}^{n\_{bl} - 2}$.

Looking forward, the same-permutation argument is only zero-knowledge provided $|\bm{r}\_{A}| \geq 2$, thus we choose $n_{bl} \geq 4$.

The prover outputs $A$ together with a proof $\pi_{sameperm}$ demonstrating that $A$ is a blinded commitment to  $\sigma(\bm{a})$ for $\sigma()$ committed to in the blinded commitment $M$.  The verifier simply checks that this proof verifies.

#####   Step 3

In the third step, the prover computes  $R = \bm{a} \times \bm{R}$ and $S = \bm{a} \times \bm{S}$ and the verifier checks that $R$ and $S$ have been computed correctly.

The prover then computes commitments $com_T = (r_T G_T, T + r_T H)$, $com_U = (r_U G_U, U + r_U H )$ to $T = k R$ and $U = k S$ respectively.
The commitments are blinded with the masking values  $r_T$ and $r_U$.
The prover then outputs $com_T, com_U$ together with a proof $\pi_{samescalar}$ demonstrating that
$com_T$ and $com_U$ open to $(T,U)$ such that $T = k R$ and $U = k S$ for the same scalar $k$.

##### Step 4

In the fourth and final step, the prover and verifier first extend $ A' = A + r_T G_T + r_U G_U$ such that $A'$ includes the blinders $r_T$ and $r_U$.

 They also extend the basis $\bm{G}$ such that $A'$ is a commitment to $\bm{x} = (\sigma(\bm{a} \\ || \\ \bm{r}\_A \ || \ r_T \\ || \\ r_U))$ under the basis $\bm{G}$.

 Now if $\bm{T}' = (\bm{T} \ || \ \bm{0} \ || \ H \ || 0 )$ for $\bm{0}$ a vector of length $n_{bl} - 2$ with every element equal to the identity element then
 \\[
 com_{T,2} = k R + r_T H = \bm{x} \times \bm{T}' = \sigma( \bm{a} ) \times \bm{T}   + r_T H
 \\]
 then we have that $k R = \sigma(\bm{a}) \times \bm{T}$ as required.  A similar argument shows that $k S = \sigma(\bm{a}) \times \bm{U}$.

Thus the prover outputs a proof $\pi_{samemultiscalar}$ demonstrating that
$com_{T}$ and $com_{U}$ contain $\sigma( \bm{a} ) \times \bm{T}$ and $\sigma( \bm{a} ) \times \bm{U}$ respectively.

##### Outcome

The prover returns the proof
\\[
\pi_{shuffle} = (A, com_T, com_U, R, S, \pi_{sameperm}, \pi_{samescalar}, \pi_{samemultiscalar}).
\\]
The verifier returns $1$ if and only if all checks pass.

## Malicious randomizer attack

The prover might attempt to trick the verifier by using a randomizer $k=0$. This results in all output ciphertexts vanishing, while the proof is still considered valid (since inputs were shuffled and a randomizer was applied). To defend against this attack, the verifier must make sure that at least the first ciphertext is not the point at infinity.
