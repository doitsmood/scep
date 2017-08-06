<?php

if(!isset($argv[1])) {
    Die('Please add client-settings file as argument\n');
}

include($argv[1]);

require 'scepHelperclass.php';
$tempWorkDir = exec("mktemp -d -t 'scepclient'");
$scep = new ScepHelper();


// create curl resource 
$ch = curl_init();

// set url 
curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=GetCACert&message=SCEP%20Authority");
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
//return the transfer as a string 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

// $output contains the output string 
$caDer = curl_exec($ch);
file_put_contents("$tempWorkDir/ca.der", $caDer);
file_put_contents("ca.der",$caDer);
exit();
exec("openssl x509 -in $tempWorkDir/ca.der -inform der -outform pem -out $tempWorkDir/ca.pem");

// Fetch CA Capabilities
curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=GetCACaps");
$capabilities = curl_exec($ch);

$caPem = file_get_contents("$tempWorkDir/ca.pem");

$request = $scep->pack($csr,$caPem,$signerCert,$signerKey);

curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=PKIOperation");                                                                      
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");                                                                     
curl_setopt($ch, CURLOPT_POSTFIELDS, $request);                                                                  
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);                                                                      
curl_setopt($ch, CURLOPT_HTTPHEADER, array(                                                                          
    'Content-Type: application/x-pki-message',                                                                                
    'Content-Length: ' . strlen($request))                                                                       
);                                                                                                                   
                                                                                                                     
$envelopedCert = curl_exec($ch);

list($signer,$degen) = $scep->unpack($envelopedCert,$signerCert,$signerKey);

echo $scep->readDegen($degen);




// close curl resource to free up system resources 
curl_close($ch);

exec("rm -rf \"$tempWorkDir\"");

?>
