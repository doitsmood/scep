<?php

class ScepHelper {

    private $_tempWorkDir;

    function __construct() {
        $this->_tempWorkDir = exec("mktemp -d -t 'scephelper'");
        print($this->_tempWorkDir);
    }

    function __destruct() {
        exec("rm -rf \"$this->_tempWorkDir\"");
    }

    /*
     * Create a valid SCEP encrypted and signed envelope
     */

    public function pack($data, $encryptCert, $signerCert, $signerKey) {
        $encryptedData = $this->_encrypt($data, $encryptCert);
        $signedData = $this->_sign($encryptedData, $signerCert, $signerKey);
        return $signedData;
    }

    /*
     *  Verify and unpack a SCEP encrypted and signed envelope
     */

    public function unpack($envelope, $encryptCert, $encryptKey) {
        list($signer, $encryptedData) = $this->_verifySignature($envelope);
        $data = $this->_decrypt($encryptedData, $encryptCert, $encryptKey);
        return $data;
    }

    /*
     * Create Degenerate PKCS7 envelope
     */

    public function createDegen($certificate) {
        file_put_contents("$this->_tempWorkDir/certificate.pem", $certificate);
        
        exec("openssl crl2pkcs7 -nocrl -certfile $this->_tempWorkDir/certificate.pem -outform DER -out $this->_tempWorkDir/degenerate.p7");
        
        return file_get_contents("$this->_tempWorkDir/degenerate.p7");
    }

    /*
     * Read certificates in Degenerate PKCS7 envelope
     */

    public function readDegen($degenerate) {
        file_put_contents("$this->_tempWorkDir/degenerateEnc.p7",$degenerate);
        
        exec("openssl pkcs7 -in $this->_tempWorkDir/degenerateEnc.p7 -inform DER -print_certs -out $this->_tempWorkDir/cert.pem");
        
        return file_get_contents("$this->_tempWorkDir/cert.pem");
    }

    /*
     * Encrypts a binary blob of data
     * 
     * The -binary option prevents the input data being converted to text
     * 
     * @data type string 
     */

    private function _encrypt($data, $encryptCert) {
        file_put_contents("$this->_tempWorkDir/date2enc", $data);
        file_put_contents("$this->_tempWorkDir/encryptioncertificate", $encryptCert);

        exec("openssl smime -encrypt -in $this->_tempWorkDir/date2enc -binary -outform DER -out $this->_tempWorkDir/encrypteddata $this->_tempWorkDir/encryptioncertificate");

        return file_get_contents("$this->_tempWorkDir/encrypteddata");
    }

    /*
     * Creates an undetached, signed PKCS7 envelope from binary data
     * 
     * Openssl smime signing, adds an smime header, in scep this should however be a PKCS7 header and footer
     * hence the additional steps
     */

    private function _sign($data, $signerCert, $signerKey) {
        file_put_contents("$this->_tempWorkDir/date2sign", $data);
        file_put_contents("$this->_tempWorkDir/signercert", $signerCert);
        file_put_contents("$this->_tempWorkDir/signerkey", $signerKey);

        exec("openssl smime -sign -nodetach -in $this->_tempWorkDir/date2sign -binary -out $this->_tempWorkDir/signeddata.smime -signer $this->_tempWorkDir/signercert -inkey $this->_tempWorkDir/signerkey -certfile $this->_tempWorkDir/signercert");
        exec("openssl smime -pk7out -in $this->_tempWorkDir/signeddata.smime -out $this->_tempWorkDir/signeddata.p7");
        exec("openssl pkcs7 -in $this->_tempWorkDir/signeddata.p7 -inform pem -outform der -out $this->_tempWorkDir/signeddata.der");

        return file_get_contents("$this->_tempWorkDir/signeddata.der");
    }

    /*
     * Verify the data in a SCEP pkcs7 envelope and extract the signer and encrypted content
     */

    private function _verifySignature($envelope) {
        file_put_contents("$this->_tempWorkDir/envelope.p7", $envelope);

        $isValid = exec("openssl smime -verify -noverify -in $this->_tempWorkDir/envelope.p7 -inform der -signer $this->_tempWorkDir/signer.pem -out $this->_tempWorkDir/encryptedData.der 2>&1");
        if (!"Verification successful" == $isValid) {
            die("Scepenvelope is not correctly signed");
        }

        return array(file_get_contents("$this->_tempWorkDir/signer.pem"), file_get_contents("$this->_tempWorkDir/encryptedData.der"));
    }

    /*
     * Decrypt the data inside SCEP-envelope
     */

    private function _decrypt($encryptedData, $encryptCert, $encryptKey) {
        file_put_contents("$this->_tempWorkDir/encData.der", $encryptedData);
        file_put_contents("$this->_tempWorkDir/encryptCert", $encryptCert);
        file_put_contents("$this->_tempWorkDir/encryptKey", $encryptKey);

        exec("openssl smime -decrypt -in $this->_tempWorkDir/encData.der -inform der -recip $this->_tempWorkDir/encryptCert -inkey $this->_tempWorkDir/encryptKey -out $this->_tempWorkDir/data");

        return file_get_contents("$this->_tempWorkDir/data");
    }

}
