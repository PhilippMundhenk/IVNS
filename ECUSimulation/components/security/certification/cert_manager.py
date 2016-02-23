from components.security.certification.certification_authority import CAHierarchy


class CertificateManager(object):
    ''' resembles the preprogrammed list of
    ECU Root Certificates'''
    
    def __init__(self, cas_hierarchy=CAHierarchy()):
        ''' Constructor
            
            Input:    cas_hierarchy    CAHierarchy    contains the hierarchy that this CA Manager uses                
            Output:   -                  
        '''
        # Certificate for ECUs & Security Modules
        self.ecu_cert = {}        
        self.sec_cert = {}
        
        # root certificates stored in ECUs & Security Modules
        self.ecu_root_cert = {}
        self.sec_mod_root_cert = {}
        
        # ca hierarchy used
        self.cas = cas_hierarchy
    
    
    def generate_valid_ecu_cert(self, ecu_id, ca_id, valid_from, valid_till, version=1.0):
        ''' This method creates a valid certificate for the ECU with ID ecu_id. Therefore the Ecu will get a 
            certificate signed by the Certification authority with ID ca_id, which is part of the initially given
            CAHierarchy that was defined earlier. 
            Additionally to creating the certificate for the ECU it is necessary to provide the necessary root certificates
            of the signing CA's  Both will be returned by this method
            
            Input:    ecu_id                    string            identifier of the ECU for which a valid certificate will be generated
                      ca_id                     CAEnum            identifier of the certification authority within the CA Hierarchy that signed this certificate
                      valid_from                float             start time of validity of this certificate
                      valid_till                float             end time of validity of this certificate
                      version                   float             certificate version
            Output:   certificate               ECUCertificate    certificate generated
                      needed_certificates_list  list              list of root certificates that are needed to verify the generated certificate
                      private_key               AsymetricKey      private key coresponding to the ECUCertificates public key
            
            '''
        
        # select CA to sign the certificate
        ca = self.cas.ca_by_id(ca_id)
        
        # generate certificate
        certificate, private_key = ca.request_user_certificate(in_version=version, in_valid_from=valid_from, in_valid_till=valid_till, user_id=ecu_id)
        
        # find root certificates for verification
        needed_certificates_list = self.get_list_needed_root_certs(certificate, valid_from, valid_till, version)
                
        return [certificate, needed_certificates_list, private_key]
    
    
    def generate_valid_ecu_cert_cfg(self, ecu_id, ca_id, sec_module_id, valid_from, valid_till, version=1.0):
        ''' This method creates a valid certificate for the ECU with ID ecu_id. Therefore the Ecu will get a 
            certificate signed by the Certification authority with ID ca_id, which is part of the initially given
            CAHierarchy that was defined earlier. 
            Additionally to creating the certificate for the ECU it is necessary to provide the necessary root certificates
            of the signing CA's to the Security Module. Only then the Security module will be able to verify the correctness 
            of the certificate.
        
            Input:    ecu_id                    string            identifier of the ECU for which a valid certificate will be generated
                      ca_id                     CAEnum            identifier of the certification authority within the CA Hierarchy that signed this certificate
                      sec_module_id             string            identifier of the Security Module that receives this certificates root certificates
                      valid_from                float             start time of validity of this certificate
                      valid_till                float             end time of validity of this certificate
                      version                   float             certificate version
            Output:   -
        '''
        
        # select CA to sign the certificate
        ca = self.cas.ca_by_id(ca_id)
        
        # generate certificate
        certificate, private_key = ca.request_user_certificate(in_version=version, in_valid_from=valid_from, in_valid_till=valid_till, user_id=ecu_id)
        
        # find root certificates for verification
        needed_certificates_list = self.get_list_needed_root_certs(certificate, valid_from, valid_till, version)
        
        # add certificates to sec. module root certificates
        try: self.sec_mod_root_cert[sec_module_id] = self.sec_mod_root_cert[sec_module_id] + needed_certificates_list
        except: self.sec_mod_root_cert[sec_module_id] = needed_certificates_list
        
        # Set certificate for the ECU
        self.ecu_cert[ecu_id] = certificate

    
    def generate_valid_sec_mod_cert_cfg(self, sec_mod_id, ca_id, ecu_id_list, valid_from, valid_till, version=1.0):
        ''' This method creates a valid certificate for the Security module with ID sec_mod_id. Therefore the Security module
            will get a certificate signed by the Certification authority with ID ca_id, which is part of the initially given
            CAHierarchy that was defined earlier. 
            Additionally to creating the certificate for the security module it is necessary to provide the necessary root certificates
            of the signing CA's to some ECUs which are listed in ecu_id_list. Only those ECUs will be able to verify the correctness 
            of the security module certificate.
        
            Input:    sec_module_id             string            identifier of the security module for which a valid certificate will be generated
                      ca_id                     CAEnum            identifier of the certification authority within the CA Hierarchy that signed this certificate
                      ecu_id_list               list              list of identifiers of ECUs that receives this certificates root certificates
                      valid_from                float             start time of validity of this certificate
                      valid_till                float             end time of validity of this certificate
                      version                   float             certificate version
            Output:   -
        '''
        
        # select CA to sign the certificate
        ca = self.cas.ca_by_id(ca_id)
        
        # generate certificate
        certificate, private_key = ca.request_user_certificate(in_version=version, in_valid_from=valid_from, in_valid_till=valid_till, user_id=sec_mod_id)
        
        # find root certificates for verification
        needed_certificates_list = self.get_list_needed_root_certs(certificate, valid_from, valid_till, version)
        
        # add certificates to given ECUs root certificates
        for ecu_id in ecu_id_list:        
            try: self.ecu_root_cert[ecu_id] = self.ecu_root_cert[ecu_id] + needed_certificates_list
            except: self.ecu_root_cert[ecu_id] = needed_certificates_list
        
        # Set certificate for the security module
        self.sec_cert[sec_mod_id] = certificate

        
    def get_list_needed_root_certs(self, certificate, valid_from, valid_till, version):
        ''' returns a list of certificates that are needed to verify this certificate
            
            Input:    certificate               ECUCertificate    certificate generated
                      valid_from                float             start time of validity of this certificate
                      valid_till                float             end time of validity of this certificate
                      version                   float             certificate version
        '''
        
        # get first
        lst_certs = [certificate]
        next_cert = certificate
        
        # iterate until self signed certificate reaached
        while True:      
            try:
                next_ca = self.cas.ca_by_id(next_cert.cert_auth)
                if next_ca == None: break
            except:
                break
            
            # get next certificate
            next_cert = next_ca.request_certificate(in_version=version, in_valid_from=valid_from, in_valid_till=valid_till)
            
            # add certificate
            lst_certs.append(next_cert)
            
        return lst_certs    
        
