// source: https://github.com/ensdomains/dnssec-oracle/blob/master/contracts/algorithms/RSAVerify.sol
// used under BSD 2-Clause License

pragma solidity >0.4.23;

import "./ModexpPrecompile.sol";

library RSAVerify {
    /**
    * @dev Recovers the input data from an RSA signature, returning the result in S.
    * @param N The RSA public modulus.
    * @param E The RSA public exponent.
    * @param S The signature to recover.
    * @return True if the recovery succeeded.
    */
    function rsarecover(bytes memory N, bytes memory E, bytes memory S) internal view returns (bool, bytes memory) {
        return ModexpPrecompile.modexp(S, E, N);
    }
}
