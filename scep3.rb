require "openssl"
DEFAULT_CIPHER_ALGORITHM = 'aes-256-cbc'
# Load the CA keys
cakey = OpenSSL::PKey::RSA.new(File.read('ca/rootCA.key'))
cacertificate = OpenSSL::X509::Certificate.new(File.read('ca/rootCA.pem'))

request = File.read('pkcs7envelope')
p7sign = OpenSSL::PKCS7.new(request)
store = OpenSSL::X509::Store.new
p7sign.verify(nil, store, nil, OpenSSL::PKCS7::NOVERIFY)
signers = p7sign.signers


degenerate_pkcs7_der = File.read('degen.der')
File.write('requesterCert',p7sign.certificates[0])
enc_cert = OpenSSL::PKCS7.encrypt(p7sign.certificates, degenerate_pkcs7_der, OpenSSL::Cipher.new(DEFAULT_CIPHER_ALGORITHM), OpenSSL::PKCS7::BINARY)
File.write('enccert.pem',enc_cert)
File.write('enccert.der',enc_cert.to_der)
reply = OpenSSL::PKCS7.sign(cacertificate, cakey, enc_cert.to_der, [cacertificate], OpenSSL::PKCS7::BINARY)
#reply = OpenSSL::PKCS7.sign(cacertificate, cakey, File.read('enccertder'), [cacertificate], OpenSSL::PKCS7::BINARY)

File.write('scepreply.pem',reply)
File.write('scepreply.der',reply.to_der)