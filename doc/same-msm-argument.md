# SameMultiscalar Argument

The *SameMultiscalar argument* proves the relation:

\\[
R_{SameMultiscalar} =
\\left\\{
\\begin{array}{l l |l}
	(A, Z_T, Z_U, \\bm{T}, \\bm{U});
	&
	\\bm{x}
	&
	A = \\bm{x} \\times \\bm{G}
	\\\\
	& &
	Z_T = \\bm{x} \\times \\bm{T}    \\\\
	& & Z_U = \\bm{x} \\times \\bm{U}
\\end{array}
\\right\\}
\\]

The SameMultiScalar argument does not depend on any subroutines.

## Protocol

A formal description of the *SameMultiScalar* argument is provided in the figure below:

<center>
<img width="90%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/same_msm_prover.png"></img>
</center>

## Informal Overview

Our SameMultiScalar relation can be seen as a form of inner product relation where one is interested in verifying
whether $A = \bm{x} \times \bm{G}$, $Z_T = \bm{x} \times \bm{T}$ and $Z_U = \bm{x} \times \bm{U}$ for some $\bm{x}$.
Inner product relations have proven popular in recent years and have been the focus both of a long line of both
academic work.  By expressing our multiscalar relation as an inner product we can thus capitalise on this preexisting
work.

In our case we consider that $A$ is a commitment to $\bm{x}$ and $\bm{T}$ is the identity commitment to $\bm{T}$.
We then wish to show that $Z_T = \bm{x} \times \bm{T}$.
Here $\bm{x}$ is private while $\bm{T}$ is known to the verifier.
For simplicity we ignore the proof that $Z_U = \bm{x} \times \bm{U}$ because this behaves identically.
The inner product argument is recursive.
At each stage of the recursion, the aim is to find new commitments $A', \bm{T}'$ to values $\bm{x}'$, $\bm{T}'$ of half the length.
Further we need a new $Z_T'$ such that $Z_T' = \bm{x}' \times \bm{T}'$ if and only if $Z_T = \bm{x} \times \bm{T}$.
After sufficient rounds of recursion we have that $\bm{x}'$ is a vector of length $1$, and thus can be sent in the clear.
The verifier checks that the inner product relation holds for the final revealed openings, and this suffices to show that the relation holds for the original longer openings.


Each round of the recursion proceeds as follows. The prover first computes auxiliary cross product commitments (that will later be used to define $A'$ and $T'$) as

\\[
    L\_A  = \\bm{x}\_{\[:n\]} \\times \\bm{G}\_{\[n:\]}, \\
    R\_A = \\bm{x}\_{\[n:\]} \\times \\bm{G}\_{\[:n\]}, \\
	L\_T  = \\bm{x}\_{\[:n\]} \\times \\bm{T}\_{\[n:\]}, \\
    R\_T  = \\bm{x}\_{\[n:\]} \\times \\bm{T}\_{\[:n\]}
\\]

These are then hashed to find a random challenge $\gamma$ .


The verifier updates the claimed inner product result to $Z_T' = \gamma L_T + Z_T + \gamma^{-1} R_T$ and the prover updates the commitment contents to
\\[
	\bm{x}'  = \bm{x}\_{\[:n\]} + \gamma^{-1} \bm{c}\_{\[n:\]}, \\
	\bm{T}'  = \bm{T}\_{\[:n\]} + \gamma \bm{T}\_{\[n:\]}
\\]
such that
$
Z_T' = \bm{x}' \times \bm{T}'
$.
See that $\bm{x}'$ and $\bm{T}'$ are half the length of $\bm{x}$ and $\bm{T}$.
We then update the commitment $A$ to $\bm{x}$ and the commitment key $\bm{G}$ as
\\[
A'  = \gamma L\_A + A + \gamma^{-1} R\_A, \
\bm{G}'  = \bm{G}\_{\[:n\]} + \gamma^{-1} \bm{G}\_{\[n:\]}
\\]
such that
$
A' = \bm{x}' \times \bm{G}'
$
is a commitment to $\bm{x}'$.

Putting this together means we have $(A', T') = (\bm{x}' \times \bm{G}', \bm{x}' \times \bm{T}')$ for some $\bm{x}'$ that is half the length of $\bm{x}$.
Due to the randomised nature of $\gamma$ this statement is true if and only if the original $(A, Z_T) = (\bm{x} \times \bm{G}, \bm{x} \times \bm{T})$ for some $\bm{x}$.
The protocol then recurses until the final round, where $\bm{x}$ and $\bm{T}$ have length $1$.  Then the prover sends $\bm{x} = x_1$ in the clear and verifier accepts if and only if $Z_T = x_1 T_1$.    Note that the full protocol has some additional masking values that are included to ensure zero-knowledge.   For simplicity we have ignored these terms in this overview.

## Full Zero Knowledge Construction

Inner product arguments are not, by default, zero-knowledge.

In order to get a zero-knowledge argument we introduce a step at the beginning to randomise the prover's witness.
In particular the prover  first blinds the argument by sampling $\bm{r}$ randomly.
They compute $B_A, B_{T}, B_{U} = (\bm{r} \times \bm{G}, \bm{r} \times \bm{T}, \bm{r} \times \bm{U})$ to blind the witness relating to $A$, $Z_T$ and $Z_U$ respectively.
They hash to obtain the field element $\alpha$.
The prover resets the private inputs to equal $\bm{r} + \alpha \bm{x}$
and the verifier resets the public inputs to equal

$A = B_A + \\alpha A$ and $Z_T = B_T + \\alpha Z_T$ and $Z_U = B_U + \\alpha Z_U$

At this point the provers private input $\bm{x}$ is fully randomised and the prover could, theoretically, reveal it in the clear.
Doing so however would increase the proof size significantly.  Instead we run the inner product argument as specified in the section above.
