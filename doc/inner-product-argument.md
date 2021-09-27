# Discrete Logarithm Inner Product Argument

The *Discrete Logarithm Inner Product argument* proves the relation:

\\[
    R_{DLInner} =
    \\left\\{
    \\begin{array}{l l|l}
    (C, D, z);  & (\bm{c}, \bm{d} )
    &
    C = \bm{c} \times \bm{G} \\\\
    & & D = \bm{d} \times \bm{G}' \\\\
    & & z = \bm{c} \times \bm{d}
    \\end{array}
    \\right\\}
\\]

This protocol was originally by [Bootle et al.](https://eprint.iacr.org/2016/263.pdf) .
We make minor adjustments in order to achieve zero-knowledge.
We did not use all the optimizations from [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) because we decided that the improvements to the proof size is not justified by the additional cost to the verifier for our application.
However we did use their method for inserting the inner product into the commitment.

## Protocol

A formal description of the *DLInner* argument is provided in the figure below:

<center>
<img width="100%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/ipa_prover.png"></img>
</center>

## Informal Overview

Our inner product relation can be seen as a form of inner product relation where one is interested in verifying whether we know $(\bm{c}, \bm{d})$ such that $C = \bm{c} \times \bm{G} + z H$,
$D = \bm{d} \times \bm{G}'$ where $z = \bm{c} \times \bm{d}$.
The inner product argument is recursive.
At each stage of the recursion, the aim is to find new commitments $C', D'$ to values $\bm{c}'$, $\bm{d}'$ of half the length.
Further we need a new $z'$ such that $z' = \bm{c}' \times \bm{d}'$ if and only if $z = \bm{c} \times \bm{d}$.
After sufficient rounds of recursion we have that $\bm{c}, \bm{d}$ are vectors of length $1$, and thus can be sent in the clear.
The verifier checks that the inner product relation holds for the final revealed openings, and this suffices to show that the relation holds for the original longer openings.

One initial subtlety is that $C$ is a commitment to $( \bm{c} \ || \ 0 )$ whereas our inner product argument assumes that $C$ is a commitment to $(\bm{c} \ || \ z)$.
We thus have an initial step where:
(1) we obtain a random challenge by hashing the public inputs $\beta = H(C, D, z)$;
(2) the verifier  updates the public input
\\[
C = C + z \beta H 
\\] 
to include $z$; (3) we update $H = \beta H$.
 Here the random $\beta$ term prevents a cheating prover from initially providing $C$ that is not a commitment to $(\ \cdot \ || \ 0 )$.


Each round of the recursion proceeds as follows. The prover first computes cross product commitments (that will later be used to define $C'$ and $C'$) as 

\\[
\\begin{align*}
& L\_C  = \bm{c}\_{\[:n\]} \times \bm{G}\_{\[n:\]} + (\bm{c}\_{\[:n\]} \times \bm{d}\_{\[n:\]} ) H \\
&&  R\_C = \bm{c}\_{\[n:\]} \times \bm{G}\_{\[:n\]} + (\bm{c}\_{\[n:\]} \times \bm{d}\_{\[:n\]} ) H \\\\
& L\_D  = \bm{d}\_{\[n:\]} \times \bm{G}\_{\[:n\]}'  \\
&&  R\_D  = \bm{d}\_{\[:n\]} \times \bm{G}\_{\[n:\]}' 
\\end{align*}
\\]

These are then hashed to find a random challenge $\gamma$ . 

The prover updates the commitment contents to 
\\[
    \bm{c}'  = \bm{c}\_{\[:n\]} + \gamma^{-1} \bm{c}\_{\[n:\]}, \\
    \bm{d}'  = \bm{d}\_{\[:n\]} + \gamma \bm{d}\_{\[n:\]},
    z = \gamma (\bm{c}\_{\[:n\]} \times \bm{d}\_{\[n:\]} ) + z + \gamma^{-1} (\bm{c}\_{\[n:\]} \times \bm{d}\_{\[:n\]} )
\\]
such that
$
z' = \bm{c}' \times \bm{d}' 
$.
See that $\bm{c}'$ and $\bm{d}'$ are half the length of $\bm{c}$ and $\bm{d}$.
We then update the commitments $C$, $D$ to $\bm{c}$, $\bm{d}$ and the commitment keys $\bm{G}$, $\bm{G}'$ as

\\[
C'  = \gamma L_C + C + \gamma^{-1} R_C, \\
D'  = \gamma L_D + D + \gamma^{-1} R_D, \\
\bm{\bar{G}}  = \bm{G}\_{\[:n\]} + \gamma \bm{G}\_{\[n:\]}, \\
\bm{\bar{G}}'  = \bm{G}\_{\[:n\]} + \gamma^{-1} \bm{G}\_{\[n:\]}
\\]

such that
$
C' = \bm{c}' \times \bm{\bar{G}} + z' H
$
is a commitment to $(\bm{c}', z')$ and $
D' = \bm{d}' \times \bm{\bar{D}} 
$
is a commitment to $\bm{d}'$ .

Putting this together means we have $(C', D') = (\bm{c}' \times \bm{\bar{G}} + z H, \bm{d}' \times \bm{\bar{G}}')$ for some $\bm{c}'$, $\bm{d}'$ that are half the length of $\bm{c}$, $\bm{d}$.
Due to the randomised nature of $\gamma$ this statement is true if and only if the original $(C, D) = (\bm{c} \times \bm{G} + (\bm{c} \times \bm{d}) H, \bm{d} \times \bm{G}')$ for some $\bm{c}$, $\bm{d}$.
The protocol then recurses until the final round, where $\bm{c}$ and $\bm{d}$ have length $1$.  Then the prover sends $\bm{c} = c_1$ and $\bm{d} = d_1$ in the clear and verifier accepts if and only if $C = c G_1 + z H$, $D = d G_1'$.    Note that the full protocol has some additional masking values that are included to ensure zero-knowledge.   For simplicity we have ignored these terms in this overview.

## Full Zero-Knowledge DL Inner Product Construction

The full zero-knowledge construction for the inner product argument is given in the figures below.  Inner product
arguments are not, by default, zero-knowledge.  In order to get a zero-knowledge argument we introduce an intermediary
step to randomise the prover's witness.

##### Step 1:

The prover blinds the argument by sampling $\bm{r}_C, \bm{r}_D$ randomly such that

$\bm{r}_C \times \bm{d} + \bm{r}_D \times \bm{c} = 0$ and $\bm{r}_C \times \bm{r}_D = 0$

Then the prover computes
\\[ 
( B_C, B_{D} ) = (\bm{r}_C \times \bm{G}, \bm{r}_D \times \bm{G}') 
\\] 
to blind the witness relating to $\bm{c}$, $\bm{d}$ respectively.

Next they hash to obtain the field elements $\alpha, \beta$.
The prover resets the private inputs to equal $\bm{r}_C + \alpha \bm{c}$ and $\bm{r}_D + \alpha \bm{d}$
and the verifier resets the public inputs to equal 

$C = B_C + \alpha C +  \alpha^2 z H$ and $D = B_D + \alpha D$. 

Observe that the updated $C$ is a commitment to $(\bm{r}_C + \alpha \bm{c},   \alpha^2 z )$ and $D$ is a commitment to 
$(\bm{r}_D + \alpha \bm{d})$.
Thus
\\[ (\bm{r}_C + \alpha \bm{c}) \times (\bm{r}_D + \alpha \bm{d}) =  \bm{r}_C \times \bm{r}_D + \alpha (\bm{r}_C \times \bm{d} + \bm{r}_D \times \bm{c}) + \alpha^2 z  \\]
and $ \alpha^2 z$ is the correct inner product of the updated commitments.

#####  Step 2

We now run the inner product argument as specified in the section above.

## Optimizations

See our [optimization notes](crate::notes::optimizations#ipa-verification-scalars) for how we further improve the
performance of the verifier.
