from io_processing.result_interpreter.abst_result_interpreter import AbstractInterpreter, \
    InterpreterOptions
from io_processing.surveillance_handler import CheckpointHandler
from tools.general import RefList, General as G
from enum import Enum
import logging


class CheckpointInterpreter(AbstractInterpreter):
    
    def __init__(self, export_options=False, file_path=False, ignore=False): 
        AbstractInterpreter.__init__(self, export_options, file_path)
        if ignore: return
        
        # CSV Output
        self.ecu_ids = RefList()        
        self.first = True
    
    def interprete_data(self, db_connection):
        ''' is invoked in certain time 
            intervals by the monitor
            
            all informations associated with the ECU are gathered 
            in CheckpointCollections      
            
            receives a result table in instead of a tuple list      
            '''
        if self.first:
            self._tmp_db = db_connection[0]    
            self.con = db_connection[1]            
            self.timing = TimingEvaluatorCore(self._tmp_db)
            self.first = False
                     
    def get_handler(self):
        ''' 
            returns the handler classes that will send their
            data to this interpreter
        '''
        return [CheckpointHandler]
    

    def on_finish(self):
        # Extract general options from Timings:    
        #                                       Sec Mod: Anzahl an Anfragen pro Sekunde bezogen auf ECU Auth. Prozess    // Absolute Anzahl an Anfragen
        #                                                Anzahl an Anfragen pro Sekunde bezogen auf Stream Auth.         // Absolute Anzahl an Anfragen
        #                                                wie lange dauert es im Schnitt von der ankommenden Anfrage bis Sec Mod diese Verarbeitet hat (Bei ECU Auth und fuer alle  Streams im Schnitt)
        #                                       pro ECU (pro Unterpunkt): Anzahl an gesendeten Nachrichten, prozentualer Anteil an gesamt Nachrichtenanzahl
        #                                                                 Durchschnittliche Nachrichtengroesse, Maximale/Minimale Nachrichten groesse
        #                            
        #                                       zw. 2 ECUs: Anzahl an empfangenen Nachrichten von ECU XY und gesendeten NAchrichten an ECU XY
        #                                        wie viel Authorization, Authentication messages wurden versendet
        
        print("Started Export...")
        # logging.info("Exporting Checkpoints...")
        # Sort information by time
        self._tmp_db.execute("SELECT * FROM Checkpoints ORDER BY Time ASC;")
        
        try:
            # was ist der overhead der dadurch produziert wird: wie viel Byte schicke ich wegen encryption jetzt mehr?
            self.msg_overhead = self.timing.calc_overhead()
            
            # Avg Authorization Time/ Authorization Time per Stream (==wie viel spaeter beginnt die Nachrichtenuebertragung im Schnitt weil noch eine Stream Request gemacht werden musste )
            [self.avg_str_auth_time, self.str_auth_time] = self.timing.avg_stream_auth_time()
            
            # Avg ECU Authentication Time / Authentication Time per ECU
            [self.avg_ecu_auth_time, self.ecu_auth_times_dict] = self.timing.avg_ecu_auth_time()
            
            # Time one byte of a message needs on average (without stream auth AND With stream auth) -> Prozentualer Increase vom einen zum anderen
            self.avg_byte_time_with_stream, self.avg_byte_time_with_stream_by_stream = self.timing.avg_byte_time_with_stream()

            # time one byte of a message needs on average, when encryption time is ignored (so how high is the increase due to the encryption) IMMER BEZOGEN AUF NUTZDATEN, nicht encrypted Datengroesse!
            self.avg_byte_time_no_stream, self.avg_byte_time_no_stream_by_stream = self.timing.avg_byte_time_no_stream()
            
            # per cent increase because of encryption
            self.per_increase_time_per_byte = (self.avg_byte_time_with_stream - self.avg_byte_time_no_stream) / self.avg_byte_time_no_stream
            
            # wie viel Prozent der gesendeten Bytes sind Authorization Nachrichten
            self.timing.calc_byte_percentages(); 
            
            # Todo: Implement more information
            
        except:
            pass
        self.con.close()
        
        # Todo: Go on here
               

        if InterpreterOptions.TIMING_FILE in self.export_options: 
            self._export_timing_vals_txt()

            

        logging.info("Export finished")

    def _export_timing_vals_txt(self):
        txt_lines = []

        txt_lines.append("Avg. Stream Authorization Time: \t%s\nAuthorization Time per Stream: \t%s" % (self.avg_str_auth_time, self.str_auth_time))
        txt_lines.append("Avg. ECU Authentication Time: \t%s \nAuthentication Time per ECU: \t%s" % (self.avg_ecu_auth_time, self.ecu_auth_times_dict))
        txt_lines.append("Time one byte of a simple message needs on average: \t%s \nTime one byte of a simple message needs on average per Stream: \t%s" % (self.avg_byte_time_with_stream, self.avg_byte_time_with_stream_by_stream))
        txt_lines.append("Time one byte of a simple message would need without encryption on average: \t%s \nTime one byte of a simple message would need without encryption on average per Stream: \t%s" % (self.avg_byte_time_no_stream, self.avg_byte_time_no_stream_by_stream))
        txt_lines.append("Simple message needs \t%s %% more time because of the encryption" % (self.per_increase_time_per_byte * 100))
        txt_lines.append("Simple message overhead due to encryption \t%s %%" % (self.msg_overhead * 100))
         
        txt_lines.append(StringBeautifier().pretty_comp_cat("Sent messages per category and ECU: \t" , self.timing.msgs_sent_per_category_and_ecu, "messages"))
        txt_lines.append(StringBeautifier().pretty_comp_cat("Received messages per category and ECU: \t" , self.timing.msgs_received_per_category_and_ecu, "messages"))
        txt_lines.append(StringBeautifier().pretty_comp_cat("Sent messages per category and ECU [per cent]: \t" , self.timing.percent_msgs_sent_per_category_and_ecu, "%"))
        txt_lines.append(StringBeautifier().pretty_comp_cat("Received messages per category and ECU [per cent]: \t" , self.timing.percent_msgs_received_per_category_and_ecu, "%"))        
        txt_lines.append(StringBeautifier().pretty_comp_cat("Sent bytes per category and ECU: \t" , self.timing.bytes_sent_per_category_and_ecu, "bytes"))        
        txt_lines.append(StringBeautifier().pretty_comp_cat("Received bytes per category and ECU: \t" , self.timing.bytes_received_per_category_and_ecu, "bytes"))        
        txt_lines.append(StringBeautifier().pretty_comp_cat("Sent bytes per category and ECU [per cent]: \t" , self.timing.percent_bytes_sent_per_category_and_ecu, "%"))        
        txt_lines.append(StringBeautifier().pretty_comp_cat("Received bytes per category and ECU [per cent]: \t" , self.timing.percent_bytes_received_per_category_and_ecu, "%"))
         
        txt_lines.append(StringBeautifier().pretty_cat("Sent bytes per category: \t,s" , self.timing.bytes_sent_per_category, "bytes"))
        txt_lines.append(StringBeautifier().pretty_cat("Sent messages per category: \t" , self.timing.msgs_sent_per_category, "messages"))
        txt_lines.append(StringBeautifier().pretty_cat("Sent bytes per category [per cent]: \t" , self.timing.percent_bytes_sent_per_category, "%"))
        txt_lines.append(StringBeautifier().pretty_cat("Sent messages per category [per cent]: \t" , self.timing.percent_msgs_sent_per_category, "%"))  
        txt_lines.append(StringBeautifier().pretty_cat("Received bytes per category: \t" , self.timing.bytes_rec_per_category, "bytes"))
         
        txt_lines.append(StringBeautifier().pretty_cat("Received messages per category: \t" , self.timing.msgs_rec_per_category, "messages"))
        txt_lines.append(StringBeautifier().pretty_cat("Received bytes per category [per cent]: \t" , self.timing.percent_bytes_rec_per_category, "%"))
        txt_lines.append(StringBeautifier().pretty_cat("Received messages per category [per cent]: \t" , self.timing.percent_msgs_rec_per_category, "%"))

        out_txt = "\n\n".join(txt_lines)
#         idx = self.file_path[::-1].find('.')
#         file_path = self.file_path[:(-idx - 1)] + "_timings_ecus.txt"
        file_path = self.file_path
        
        with open(file_path, "w") as text_file:
            text_file.write(out_txt)
            
        print("wrote checkpoints results to %s" % file_path)

  
    @property
    def file_path(self):
        return self._file_path
    
    @file_path.setter
    def file_path(self, val):
        self._file_path = val
        try:
            self.core.init_csv(self._file_path)
        except:
            pass
                       
class TimingEvaluatorCore(object):
    
    def __init__(self, db_cur):
        self._db_cur = db_cur  # database with checkpoint information

    def avg_stream_auth_time(self):
        ''' time it takes from Moment the ECU requests a
            stream until ECU starts to send the message.
            So the average time a stream request needs. From the 
            moment the ecu decides to sent until it really starts to send
            
            from CP_ECU_START_CREATE_REQ_MESSAGE until 
                CP_ECU_RECEIVE_GRANT_MESSAGE
            '''
        auth_str_time = {}
        
        # find all end times
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE'")
        end_data = self._db_cur.fetchall()
                            
        # check time differences        
        str_times = []
        for end_d in end_data:
            try:
                self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE' AND MonitorId = '%s' AND StreamId = %s" % (end_d[1], end_d[7]))
                start_time = self._db_cur.fetchall()[-1][0]
                end_time = end_d[0]
                
                str_times.append(end_time - start_time)
                G().add_to_three_dict(auth_str_time, end_d[1], end_d[7], end_time - start_time)
            except:
                pass    
        try:
            res = sum(str_times) / float(len(str_times))
        except:
            res = -1
        return [res, auth_str_time]
    
    def avg_byte_time_no_stream(self):
        '''
        returns the time one byte of Nutzdaten(!) of a message would need if no 
        encryption was made
        
        So per Stream from CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE
        to CP_ECU_RECEIVE_SIMPLE_MESSAGE
        '''

        # check all times
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE'")
        end_data = self._db_cur.fetchall()

        # Avg Byte duration per stream
        dur_stream = {}    
        for end_d in end_data:
            try:
                self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE' AND UniqueId = '%s'" % end_d[8])
                start_d = self._db_cur.fetchall()
                start_time = start_d[0][0]
                
                self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE' AND UniqueId = '%s'" % end_d[8])
                start_d = self._db_cur.fetchall()
                m_size = start_d[0][6]
                
                G().force_add_dict_list(dur_stream, end_d[7], (end_d[0] - start_time) / float(m_size))
            
            except:
                pass


        # all Durations per stream
        avg_dur_stream = {}
        
        for msg_stream in dur_stream.keys():
            # calc average
            try:
                avg_dur_stream[msg_stream] = sum(dur_stream[msg_stream]) / float(len(dur_stream[msg_stream]))
            except:
                pass
                
        # Average duration of all streams
        lst = []
        for ky in avg_dur_stream.keys():
            lst.append(avg_dur_stream[ky])
                
        try:
            avg_all_streams = sum(lst) / float(len(lst))
        except:
            avg_all_streams = -1
            
        return [avg_all_streams, avg_dur_stream]
    
    def avg_byte_time_with_stream(self):
        '''
        returns the time one byte of Nutzdaten(!) of a message needs on average from the
        sender before encryption to the receiver after encryption
        
        So per Stream from CP_ECU_INTENT_SEND_SIMPLE_MESSAGE
        to CP_ECU_DECRYPTED_SIMPLE_MESSAGE
        
        '''
        
        # per stream gather
        # check all times
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE'")
        end_data = self._db_cur.fetchall()

        # Avg Byte duration per stream
        dur_stream = {}    
        for end_d in end_data:
            try:
                self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE' AND UniqueId = '%s'" % end_d[8])
                start_d = self._db_cur.fetchall()
                start_time = start_d[0][0]
                m_size = start_d[0][6]
                G().force_add_dict_list(dur_stream, end_d[7], (end_d[0] - start_time) / float(m_size))
            
            except:
                pass
                    
        # all Durations per stream
        avg_dur_stream = {}        
        for msg_stream in dur_stream.keys():
            # calc average
            try:
                avg_dur_stream[msg_stream] = sum(dur_stream[msg_stream]) / float(len(dur_stream[msg_stream]))
            except:
                pass
                
        # Average duration of all streams
        lst = []
        for ky in avg_dur_stream.keys():
            lst.append(avg_dur_stream[ky])                
        try:
            avg_all_streams = sum(lst) / float(len(lst))
        except:
            avg_all_streams = -1
            
        return [avg_all_streams, avg_dur_stream]
            
    def avg_ecu_auth_time(self):
        '''
        time the average ecu Authentication takes
        from CP_SEC_INIT_AUTHENTICATION until 
        CP_ECU_DECRYPTED_CONF_MESSAGE
        '''
        try:
            dur_per_ecu = {}
            
            # start time
            self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_SEC_INIT_AUTHENTICATION'")
            start_time = self._db_cur.fetchall()[0][0]
            
            # find all end times
            self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE'")
            end_data = self._db_cur.fetchall()
                                
            # check time differences        
            str_times = []
            for end_d in end_data:
                try:                            
                    end_time = end_d[0]
                    
                    str_times.append(end_time - start_time)
                    dur_per_ecu[end_d[1]] = end_time - start_time
                except:
                    pass    
            try:
                res = sum(str_times) / float(len(str_times))
            except:
                res = -1
            return [res, dur_per_ecu]
        except:
            return [-1, {}]
    
    def calc_byte_percentages(self):
        '''
        percentage of bytes and (number of messages) sent that make up for 
        the simple message category,
        for the ecu auth category and the 
        stream auth category       
        
        excluding the Security Module: only the messages the ECUs produce
        
        per ECU: how many of the bytes that I sent were
        of type 1, 2 or 3
        
        per Ecu and in total
        '''
        
        msg_sizes_sent = {}
        msg_sizes_rec = {}       
        
        # Simple send/receive
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE'")
        sent = self._db_cur.fetchall()
        for sd in sent:
            G().force_add_dict_list_2(msg_sizes_sent, "SIMP_MSG", sd[1], sd[6])
            
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE'")
        recs = self._db_cur.fetchall()
        for rd in recs:
            G().force_add_dict_list_2(msg_sizes_rec, "SIMP_MSG", rd[1], rd[6])                        
            
        # ECU send/receive
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_SEND_REG_MESSAGE'")
        sent = self._db_cur.fetchall()
        for sd in sent:
            G().force_add_dict_list_2(msg_sizes_sent, "ECU_AUTH", sd[1], sd[6])
            
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE'")
        recs = self._db_cur.fetchall()
        for rd in recs:
            G().force_add_dict_list_2(msg_sizes_rec, "ECU_AUTH", rd[1], rd[6])            
        
        # Str Auth send/receive
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE'")
        sent = self._db_cur.fetchall()
        for sd in sent:
            G().force_add_dict_list_2(msg_sizes_sent, "STR_AUTH", sd[1], sd[6])
        
        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE'")
        recs = self._db_cur.fetchall()
        for rd in recs:
            G().force_add_dict_list_2(msg_sizes_rec, "STR_AUTH", rd[1], rd[6])                              
                    
        # Absolute number of bytes sent per ecu
        abs_sent = {}
        abs_sent_msgs = {}
        abs_rec = {}
        abs_rec_msgs = {}
        for ky in msg_sizes_sent:
            for kky in msg_sizes_sent[ky].keys():
                if kky not in abs_sent.keys(): abs_sent[kky] = []
                abs_sent[kky] += msg_sizes_sent[ky][kky]
                  
        for ky in abs_sent.keys():
            abs_sent_msgs[ky] = len(abs_sent[ky])
            abs_sent[ky] = sum(abs_sent[ky])
            
        # Same for received bytes
        for ky in msg_sizes_rec:
            for kky in msg_sizes_rec[ky].keys():
                if kky not in abs_rec.keys(): abs_rec[kky] = []
                abs_rec[kky] += msg_sizes_rec[ky][kky]
                  
        for ky in abs_rec.keys():
            abs_rec_msgs[ky] = len(abs_rec[ky])
            abs_rec[ky] = sum(abs_rec[ky])
            
                    
        # Percentage of messages  per category
        msg_percentage_bytes_sent = {}
        msg_abs_bytes_sent = {}
        msg_abs_sent = {}
        msg_percentage_abs_sent = {}
        for ky in msg_sizes_sent:
            for kky in msg_sizes_sent[ky]:
                try:
                    G().add_to_three_dict(msg_abs_sent, kky, ky, len(msg_sizes_sent[ky][kky]))      
                    G().add_to_three_dict(msg_abs_bytes_sent, kky, ky, sum(msg_sizes_sent[ky][kky]))     
                    G().add_to_three_dict(msg_percentage_abs_sent, kky, ky, float(len(msg_sizes_sent[ky][kky])) / float(abs_sent_msgs[kky]))    
                    G().add_to_three_dict(msg_percentage_bytes_sent, kky, ky, sum(msg_sizes_sent[ky][kky]) / float(abs_sent[kky]))
                except:
                    pass

        msg_percentage_bytes_rec = {}
        msg_abs_rec = {}
        msg_abs_bytes_rec = {}
        msg_percentage_abs_rec = {}
        for ky in msg_sizes_rec:
            for kky in msg_sizes_rec[ky]:
                try:
                    G().add_to_three_dict(msg_abs_rec, kky, ky, len(msg_sizes_rec[ky][kky]))            
                    G().add_to_three_dict(msg_abs_bytes_rec, kky, ky, sum(msg_sizes_rec[ky][kky]))     
                    G().add_to_three_dict(msg_percentage_abs_rec, kky, ky, float(len(msg_sizes_rec[ky][kky])) / float(abs_rec_msgs[kky]))        
                    G().add_to_three_dict(msg_percentage_bytes_rec, kky, ky, sum(msg_sizes_rec[ky][kky]) / float(abs_rec[kky]))
                except:
                    pass

        # messages sent per category not per ecu
        msg_abs_sent_all = {}
        msg_bytes_sent_all = {}
        all_sizes = 0
        all_bytes = 0
        for ky in msg_abs_sent:
            for cat in ["SIMP_MSG", "ECU_AUTH", "STR_AUTH"]:
                try:
                    nr = msg_abs_sent[ky][cat]
                except:
                    msg_abs_sent[ky][cat] = 0
                    nr = 0        
                try:
                    nr_b = msg_abs_bytes_sent[ky][cat]
                except:
                    msg_abs_bytes_sent[ky][cat] = 0
                    nr_b = 0
                try:
                    all_sizes += nr
                    all_bytes += nr_b
                    
                    msg_abs_sent_all[cat] += nr
                    msg_bytes_sent_all[cat] += nr_b
                                        
                except:
                    msg_abs_sent_all[cat] = nr
                    msg_bytes_sent_all[cat] = nr_b
                
        perc_abs_sent = {}
        perc_bytes_sent = {}
        for cat in msg_abs_sent_all.keys():
            try:
                perc_abs_sent[cat] = float(msg_abs_sent_all[cat]) / float(all_sizes)
                perc_bytes_sent[cat] = float(msg_bytes_sent_all[cat]) / float(all_bytes)
            except:
                pass
            
        # receive
        msg_abs_rec_all = {}
        msg_bytes_rec_all = {}
        all_sizes = 0
        all_bytes = 0
        for ky in msg_abs_rec:
            for cat in ["SIMP_MSG", "ECU_AUTH", "STR_AUTH"]:
                try:
                    nr = msg_abs_rec[ky][cat]
                except:
                    msg_abs_rec[ky][cat] = 0
                    nr = 0        
                try:
                    nr_b = msg_abs_bytes_rec[ky][cat]
                except:
                    msg_abs_bytes_rec[ky][cat] = 0
                    nr_b = 0
                try:
                    all_sizes += nr
                    all_bytes += nr_b
                    
                    msg_abs_rec_all[cat] += nr
                    msg_bytes_rec_all[cat] += nr_b
                    
                    
                except:
                    msg_abs_rec_all[cat] = nr
                    msg_bytes_rec_all[cat] = nr_b
                
        perc_abs_rec = {}
        perc_bytes_rec = {}
        for cat in msg_abs_rec_all.keys():
            try:
                perc_abs_rec[cat] = float(msg_abs_rec_all[cat]) / float(all_sizes)
                perc_bytes_rec[cat] = float(msg_bytes_rec_all[cat]) / float(all_bytes)
            except:
                    pass
            
        # results - per category - per ECU
        self.msgs_sent_per_category_and_ecu = msg_abs_sent; 
        self.msgs_received_per_category_and_ecu = msg_abs_rec; 
        # this in percent
        self.percent_msgs_sent_per_category_and_ecu = G().fill_keys_2(msg_percentage_abs_sent, ["SIMP_MSG", "ECU_AUTH", "STR_AUTH"], 0); 
        self.percent_msgs_received_per_category_and_ecu = G().fill_keys(msg_percentage_abs_rec, ["SIMP_MSG", "ECU_AUTH", "STR_AUTH"], 0); 
        
        self.bytes_sent_per_category_and_ecu = msg_abs_bytes_sent; 
        self.bytes_received_per_category_and_ecu = msg_abs_bytes_rec; 
        # this in percent
        self.percent_bytes_sent_per_category_and_ecu = G().fill_keys_2(msg_percentage_bytes_sent, ["SIMP_MSG", "ECU_AUTH", "STR_AUTH"], 0); 
        self.percent_bytes_received_per_category_and_ecu = G().fill_keys_2(msg_percentage_bytes_rec, ["SIMP_MSG", "ECU_AUTH", "STR_AUTH"], 0); 
        
        # results - per category
        self.bytes_sent_per_category = msg_bytes_sent_all; 
        self.msgs_sent_per_category = msg_abs_sent_all; 
        
        self.percent_bytes_sent_per_category = perc_bytes_sent; 
        self.percent_msgs_sent_per_category = perc_abs_sent; 
        
        self.bytes_rec_per_category = msg_bytes_rec_all; 
        self.msgs_rec_per_category = msg_abs_rec_all; 
        
        self.percent_bytes_rec_per_category = perc_bytes_rec; 
        self.percent_msgs_rec_per_category = perc_abs_rec; 
    
    def calc_overhead(self):
        ''' This method gets all sizes of the encrypted simple messages
             before and after encrytion
             
             Then the overhead due to encryption is calculated
        '''
        
        # 1. per stream gather 
        enc_sizes = {}  # all start times when streams are sent: always one sender anyway
        clear_sizes = {}

        self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE'")
        enc_data = self._db_cur.fetchall()

        for enc_dat in enc_data:      
            try:      
                self._db_cur.execute("SELECT * FROM Checkpoints WHERE MonitorTag = 'MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE' AND UniqueId = '%s'" % enc_dat[8])
                start_d = self._db_cur.fetchall()
                G().force_add_dict_list(clear_sizes, start_d[0][7], start_d[0][6])
                G().force_add_dict_list(enc_sizes, enc_dat[7], enc_dat[6])
            except:pass

        lst_more = []
        lst_clear = []
        for ky in enc_sizes.keys():
            try:
                lst_more.append(self._mean(enc_sizes[ky]) - self._mean(clear_sizes[ky]))
                lst_clear.append(self._mean(clear_sizes[ky]))
            except:
                pass
        
        return (self._mean(lst_more) / self._mean(lst_clear))
        
    def _mean(self, lst):
        
        try:
            ret = float(sum(lst)) / float(len(lst))
        except:
            ret = 1
        return ret
        
        
class Checkpoint(object):
    
    def __init__(self, time=None, comp_id=None, asc_comp_id=None, asc_category=None, mon_tag=None, data=None):
        self.time = time
        self.comp_id = comp_id
        self.asc_comp_id = asc_comp_id 
        self.asc_category = asc_category
        self.mon_tag = mon_tag
        self.data = data
        
        self.msg_content = None
        self.msg_size = None
        self.msg_stream = None
        self.msg_id = None
               
class CPCategory(Enum):
    ECU_AUTHENTICATION_TRANS = 0
    ECU_AUTHENTICATION_ENC = 1   
        
    STREAM_AUTHORIZATION_TRANS = 2
    STREAM_AUTHORIZATION_ENC = 3     
        
    SIMPLE_MESSAGE_TRANS = 4
    SIMPLE_MESSAGE_ENC = 5
        
class CheckpointCollection(object):
    '''
    stores all checkpoints per ECU
    and checkpoints that are associated to another ECU    
    '''
        
    def __init__(self, _comp_id):
        self._comp_id = _comp_id        
        self.checkpoints = []
        
    def add(self, new_cp):
        self.checkpoints.append(new_cp)
        
class StringBeautifier(object):
    
    def __init__(self, *args, **kwargs):
        object.__init__(self, *args, **kwargs)

    def pretty_comp_cat(self, intro_txt, comp_cat_dict, units=""):
        try:
            hash_line = "##########################################################################################"
            newline = "\n"
            tab = "\t"
            template = "\n\n\tComponent: \t%s\n\tCategory: \t%s\n\tValue: \t\t%s %s"
            
            res_str = hash_line + newline + tab + tab + intro_txt + newline + hash_line
            
            for comp in comp_cat_dict.keys():
                try:
                    for cat in comp_cat_dict[comp].keys():
                        try:
                            res_str += newline
                            res_str += (template % (comp, cat, comp_cat_dict[comp][cat], units))
                        except:
                            pass
                except:
                    pass
                
            return res_str 
        except:
            ""
    
    def pretty_cat(self, intro_txt, cat_dict, units=""):
        try:
            hash_line = "##########################################################################################"
            newline = "\n"
            tab = "\t"
            template = "\n\n\tCategory: \t%s\n\tValue: \t\t%s %s"
            
            res_str = hash_line + newline + tab + tab + intro_txt + newline + hash_line
            
            for cat in cat_dict:
                try:
                    res_str += newline
                    res_str += (template % (cat, cat_dict[cat], units))
                except:
                    pass
                
            return res_str 
        except:
            ""
        
        
        
        
        
        
        
        
        
        
        
        
