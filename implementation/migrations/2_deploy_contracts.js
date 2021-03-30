const CertStore = artifacts.require("CertificateStore");
const SignatureValidation = artifacts.require("SignatureValidation");
const InternalEndorsement = artifacts.require("InternallyEndorsed");
const EndStore = artifacts.require("EndorsementDatabase");
const Verifier = artifacts.require("Verifier");

module.exports = function(deployer) {
	deployer.deploy(SignatureValidation);

	deployer.link(SignatureValidation, CertStore);
	deployer.link(SignatureValidation, EndStore);

	deployer.deploy(CertStore).then(function(){
	  	return  deployer.deploy(EndStore, CertStore.address).then(function(){
	  		return deployer.deploy(Verifier, EndStore.address, 0).then(function(){
	  			//return  deployer.deploy(InternalEndorsement, EndStore.address, Verifier.address)
	  			return  deployer.deploy(InternalEndorsement, EndStore.address)
	  		});
	  	});
	});
  	//deployer.deploy(InternalEndorsement, {from: "0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0"});
};
