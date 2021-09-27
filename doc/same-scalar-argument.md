# SameScalar Argument

The *SameScalar argument* proves the relation:

\\[
R_{samescalar} =
\\left\\{
\\begin{array}{l l| l}
	(R,S, com_{T}, com_{U} )  ; & (k, r_U, r_T)
	&
	com_{T} = GroupCommit( (G_{T}, H); \\ k R; \\ r_T )   \\\\
	& &  com_{U} = GroupCommit( (G_{U}, H); \\ k S; \\ r_U )
\\end{array}
\\right\\}
\\]

It demonstrates that given public input $(R,S, com_T, com_U )$ there exists $k$ such that $com_T$ is a [commitment](crate::commitments) to $T = k R$  and $com_U$ is a commitment to  $k S$.

The same scalar argument does not depend on any subroutines.

## Protocol

A formal description of the *SameScalar* argument is provided in the figure below:

<center>
<img width="90%" src="https://github.com/asn-d6/curdleproofs/raw/main/doc/images/samescalar.png"></img>
</center>

## Full Zero-Knowledge Construction

The protocol is a simple sigma-protocol and makes use of the additive homomorphism of the [commitment scheme](crate::commitments).

In order to convince the verifier the prover chooses a random statement that satisfies the same-scalar relation.
In other words it chooses a random scalar $r_k$ and computes two group elements $A = r_k R$ and $B= r_k S$ with the same scalar.

The prover then outputs the commitments:
(1) $com_A$ a commitment to $A$ under randomness $r_A$;
and (2)  $com_B$ a commitment to $B$ under randomness $r_B$.
These commitments are hashed, together with the instance, to get a challenge $\\alpha$.

The commitment scheme is homomorphic and thus
$com_A + \\alpha com_T$ is a commitment to $A + \\alpha T$ where $T$ is the contents of $com_T$.
Similarly $com_B + \\alpha com_U$ is a commitment to $B + \\alpha U$ where $U$ is the contents of $com_U$.
If $T = k R$, $U = k S$, $A = r_k R$, and $B = r_k S$ then we have that $A + \\alpha T$ and $B + \\alpha U$ have the same scalar (namely $r_k + \\alpha k$).
This is negligibly unlikely to occur if either $T$ and $U$ or $A$ and $B$ do not have the same scalar because $\\alpha$ is chosen randomly.

Thus the prover returns $z_k = r_k + \\alpha k$ together with the commitment randomness $z_T = r_T + \\alpha r_A$ and $z_U = r_k + \\alpha r_B$.
The verifier checks that
(1) $com_A + \\alpha com_T$ is a commitment to $z_k R$ under randomness $z_T$;
and (2) $com_B + \\alpha com_U$ is a commitment to $z_k S$ under randomness $z_U$.
