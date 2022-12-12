# Server code
import os
import sys
import pgpy

# Signing the list of trusted authors with the X.509 private key
def sign_list(list_file):
    # Read the list of trusted authors from the file
    with open(list_file, 'rb') as f:
        trusted_list = f.read()
    
    # Open the X.509 private key
    with open('x509_private_key.asc', 'rb') as priv_key:
        private_key = pgpy.PGPKey.from_file(priv_key)
    
    # Sign the list with the private key
    signature = private_key.sign(trusted_list)
    
    # Write the signed list to a file
    with open('signed_list.asc', 'wb') as f:
        f.write(signature.__str__())
    
    print('List signed successfully.')

# Providing the document and its signature
def provide_document(doc_file):
    # Read the document from the file
    with open(doc_file, 'rb') as f:
        document = f.read()
    
    # Open the PGP private key
    with open('pgp_private_key.asc', 'rb') as priv_key:
        private_key = pgpy.PGPKey.from_file(priv_key)
    
    # Sign the document with the private key
    signature = private_key.sign(document)
    
    # Write the signed document and its signature to a file
    with open('signed_doc.asc', 'wb') as f:
        f.write(signature.__str__())
    
    print('Document signed successfully.')

# Main function
def main():
    if len(sys.argv) < 3:
        print('Usage: server.py <operation> <file>')
        sys.exit(1)
    
    # Get the operation and file name from the command line
    operation = sys.argv[1]
    file_name = sys.argv[2]
    
    # Check if the file exists
    if not os.path.exists(file_name):
        print('Error: file does not exist.')
        sys.exit(1)
    
    # Call the appropriate function
    if operation == 'sign_list':
        sign_list(file_name)
    elif operation == 'provide_document':
        provide_document(file_name)
    else:
        print('Error: invalid operation.')
        sys.exit(1)

# Run the program
if __name__ == '__main__':
    main()
