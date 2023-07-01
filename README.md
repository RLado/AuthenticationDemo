# Authentication server demo

This is a very simple demo project to test user authentication on a webapp

## How to create a self-signed TLS certificate for testing

You can create a self-signed certificate for testing purposes. Using openSSL do:

1. Install OpenSSL on your machine.
2. Open a command prompt and navigate to the directory where you want to create the certificate.
3. Run the following command to generate a private key:

   ```
   openssl genrsa -out key.pem 2048
   ```

4. Run the following command to generate a certificate signing request (CSR):

   ```
   openssl req -new -key key.pem -out csr.pem
   ```

5. Run the following command to generate a self-signed certificate:

   ```
   openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem
   ```

This will create a self-signed certificate named `cert.pem` that is valid for 365 days.