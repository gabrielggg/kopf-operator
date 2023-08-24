# main.py
import kopf
import logging
import ssl
import socket
import kubernetes
import base64
import subprocess as sp

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    #settings.networking.connect_timeout = 10
    settings.watching.client_timeout = 30

@kopf.on.field(
    'deployments',
    field='metadata.annotations',
    annotations={'my-custom-annotation': 'true'}
)
def annotations_changed(name, spec, logger, namespace, annotations, **kwargs):
    #print("annotation detected")
    #print(f"And here we are! Created {name} with spec: {spec}")
    logging.info(f"A handler is called  with anotacion: {annotations['test']}. Nueva annotation!")
    #certi = getCertificate("wikipedia.org",443)
    lista = annotations['test']
    li = list(lista.split(","))
    for server in li:
      certi = getCertificate(server,443)
      logging.info(certi.not_valid_after)
      sendCertificateToFile("tmp.txt",certi)
      #print(certi)
      certvar = open("tmp.txt", "r").read()
      logging.info(certvar)
      #certvar = bytes(certvar, 'ascii')
      stringcerti= sp.getoutput('cat tmp.txt | base64 -w0')
      logging.info(stringcerti)
      cm={

          "cert": stringcerti

      }
      expiry={
              "valid_to": certi.not_valid_after
      }
      api = kubernetes.client.CoreV1Api()
      body = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(name=server, annotations=expiry),
        kind="Secret",
        api_version="v1",
        data=cm
      )
      #obj = api.create_namespaced_secret(
      #    namespace=namespace,
      #    body=body
      #)
      try:
        #api_response = api_instance.create_namespaced_secret(namespace, body, pretty=pretty, dry_run=dry_run, field_manager=field_manager, field_validation=field_validation)
        api_response = api.create_namespaced_secret(
          namespace=namespace,
          body=body
        )
        print(api_response)
        logging.info(api_response)
      except:
        #print("Exception when calling CoreV1Api->create_namespaced_secret: %s\n" % e)
        logging.info("error al crear secreto")


def getCertificate(__hostname: str, __port: int) -> x509.Certificate:
    """Retrieves the certificate from the website."""
    try:
        # Create the SSL context
        #if not args.insecure:
        sslContext = ssl.create_default_context()
        #else:
        #    sslContext = ssl._create_unverified_context()

        with socket.create_connection((__hostname, __port)) as sock, sslContext.wrap_socket(sock, server_hostname=__hostname) as sslSocket:
            # Get the certificate from the connection, convert it to PEM format.
            sslCertificate = ssl.DER_cert_to_PEM_cert(sslSocket.getpeercert(True))

        # Load the PEM formatted file.
        sslCertificate = x509.load_pem_x509_certificate(sslCertificate.encode('ascii'))

    except ssl.SSLCertVerificationError as e:
        print(f"SSL Verification error. {e.verify_message}\nTry with the --insecure option.")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Connection refused to {__hostname}:{__port}")
        sys.exit(1)

    # Return the sslCertificate object.
    return sslCertificate


def sendCertificateToFile(__filename: str, __sslCertificate: x509.Certificate) -> None:
    """Write the certificate in PEM format to file."""
    with open(__filename, "wb") as f_clientPublicKey:
        f_clientPublicKey.write(
            __sslCertificate.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        )
