<?php

require 'scepHelperclass.php';

$scep = new ScepHelper();

$baseUrl = "http://10.0.1.18:8042/scepserver.php";



// create curl resource 
$ch = curl_init();

// set url 
curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=GetCACert");

//return the transfer as a string 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

// $output contains the output string 
$caDer = curl_exec($ch);
file_put_contents("ca.der", $caDer);
exec("openssl x509 -in ca.der -inform der -outform pem -out ca.pem");

// Fetch CA Capabilities
curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=GetCACaps");
$capabilities = curl_exec($ch);

$signerCert = file_get_contents('clientCerts/scepsigner.pem');
$signerKey = file_get_contents('clientCerts/scepsigner.key');
$csr = file_get_contents('clientCerts/scep1.csr.der');
$caPem = file_get_contents('ca.pem');

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

$degen = $scep->unpack($envelopedCert,$signerCert,$signerKey);

echo $scep->readDegen($degen);




// close curl resource to free up system resources 
curl_close($ch);

?>
