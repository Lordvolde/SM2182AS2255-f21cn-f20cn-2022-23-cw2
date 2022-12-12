# Client code
import os
import sys
import pgpy

# Receive and check the list of trusted authors
def receive_check_list(list_file):
    # Read the list of trusted authors from the file
    with open(list_file, 'rb') as f:
        trusted_list = f.read()
    
    # Open the X.509 certificate
    with open('x509_cert.asc', 'rb') as cert:
        x509_cert = pgpy.PGPKey.from_file(cert)
    
    # Verify the list with the certificate
    if not x509_cert.verify(trusted_list):
        print('Error: list not verified.')
        sys.exit(1)
    
    print('List verified successfully.')

# Receive and check the broadcasted document
def receive_check_doc(doc_file):
    # Read the document from the file
    with open(doc_file, 'rb') as f:
        document = f.read()
    
    # Read the list of trusted authors from the file
    with open('trusted_list.asc', 'rb') as f:
        trusted_list = f.read()
    
    # Open the list of trusted authors' PGP certificates
    trusted_list_keys = pgpy.PGPKeyring.from_file('trusted_list_keys.asc')
    
    # Verify the document with the PGP certificates
    if not trusted_list_keys.verify(document, trusted_list):
        print('Error: document not verified.')
        sys.exit(1)
    
    print('Document verified successfully.')

# Main function
def main():
    if len(sys.argv) < 3:
        print('Usage: client.py <operation> <file>')
        sys.exit(1)
    
    # Get the operation and file name from the command line
    operation = sys.argv[1]
    file_name = sys.argv[2]
    
    # Check if the file exists
    if not os.path.exists(file_name):
        print('Error: file does not exist.')
        sys.exit(1)
    
    # Call the appropriate function
    if operation == 'receive_check_list':
        receive_check_list(file_name)
    elif operation == 'receive_check_doc':
        receive_check_doc(file_name)
    else:
        print('Error: invalid operation.')
        sys.exit(1)

# Run the program
if __name__ == '__main__':
    main() 
