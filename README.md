# Mirroring Public Key Infrastructures to Blockchains for On-Chain Authentication
> 5<sup>th</sup> Workshop on Trusted Smart Contracts In Association with Financial Cryptography 2021

Ulrich Gallersdörfer<sup>1</sup>, Friederike Groschupp<sup>2</sup> and Florian Matthes<sup>1</sup>

<sup>1</sup> Technical University Munich, Munich, Germany
{[ulrich.gallersdoerfer](mailto:ulrich.gallersdoerfer@tum.de),[matthes](mailto:matthes@tum.de)}@tum.de

<sup>2</sup> Department of Computer Science, ETH Zurich, Switzerland
[friederike.groschupp@inf.ethz.ch](mailto:friederike.groschupp@inf.ethz.ch)



## Abstract
> In blockchain systems, the lack of established identity management processes pose a problem for applications requiring smart contract owners to be authenticated. One issue that previously proposed solutions face is the accumulation of a critical mass of trusted data that makes the system usable. In this work, we propose an identity assertion and verification framework for Ethereum that overcomes this bootstrapping problem. It achieves this by leveraging TLS certificates, which are part of the established infrastructure that is commonly used for authenticating internet connections. We design and implement an TLS certificate-based authentication framework whose key features are the smart contract-based validation and storage of certificates and address-identity bindings. Looking at the current TLS ecosystem, we find that a large share of all domain certificates is issued by a small number of intermediate and root certificates. Therefore, we decide to store and maintain certificates in one smart contract to minimize processing costs. The evaluation of our prototype implementation shows that the associated cost of our system is within a feasible operating range, with the costs of submitting a new certificate currently averaging around $1.81 and the cost of creating an address-identity binding averaging around $1.32. Our system is a pragmatic and, most importantly, quickly bootstrapped method for an identity assertion and verification framework for Ethereum.

## Presentation & Slides
The presentation is available on [YouTube](https://www.youtube.com/watch?v=eAd8-nQoaQ4), the slides are available [here](slides/slides.pdf).

## Paper
The submission-ready paper (without author affiliation) is available [here](https://fc21.ifca.ai/wtsc/WTSC21paper6.pdf).

## Code
The code can be found in the directory `/implementation`.

To deploy and fill with Alexa certificates: 
	
	cd implementation
	ganache-cli --allowUnlimitedContractSize -l 90000000 -d

	Second window:
	cd implementation
	truffle console
	> migrate --reset
	> exec setupar.js
	> exec setupai.js
	> exec setupas.js #takes several minutes, comment lines in document out for shorter run