import os

def main(argv):
    
    seed = False  # if seed used put it in here    
    numberOfECUs_min = 2
    numberOfECUs_max = 2
    simtime = 50000
    receiveBuffer = 20000000
    sendBuffer = 20000000
    buses_min = 1
    buses_max = 1
    msgs_min = 5
    msgs_max = 5
    streamPerECU_MAD = 0.2
    receiversPerStreamCoeff = 0.2
    receiversPerStreamRand = 1
    ecu_lib = 'CyaSSL'
    sec_mod_lib = 'CyaSSL'
    
    #===========================================================================
    #     Parser arguments
    #===========================================================================
    
    parser = argparse.ArgumentParser(description='Creates a testcase and runs the simulation')
    parser.add_argument("-e", "--ecus", type=int, help="set number of ECUs (min=max)")
    parser.add_argument("-en", "--ecus_min", type=int, help="set minimum number of ECUs")
    parser.add_argument("-ex", "--ecus_max", type=int, help="set maximum number of ECUs")
    parser.add_argument("-t", "--simtime", type=int, help="set simulation time")
    parser.add_argument("-rb", "--rcv_buf", type=int, help="set receive buffer")
    parser.add_argument("-sb", "--snd_buf", type=int, help="set send buffer")
    parser.add_argument("-b", "--buses", type=int, help="set number of buses (min=max)")
    parser.add_argument("-bn", "--buses_min", type=int, help="set minimum number of buses")
    parser.add_argument("-bx", "--buses_max", type=int, help="set maximum number of buses")
    parser.add_argument("-m", "--msgs", type=int, help="set number of messages (min=max)")
    parser.add_argument("-mn", "--msgs_min", type=int, help="set minimum number of messages")
    parser.add_argument("-mx", "--msgs_max", type=int, help="set maximum number of messages")
    parser.add_argument("-s", "--streams_per_ecu", type=float, help="set streams per ECU (Median Absolute Deviation) (0..1)")
    parser.add_argument("-r", "--receivers_per_stream", type=float, help="set receivers per stream coefficient (0..1)")
    parser.add_argument("-rr", "--receivers_per_stream_randomize", type=float, help="set receivers per stream coefficient randomization factor (+/- x)")
    parser.add_argument("-q", "--ecu_lib", type=str, help="set ECU library")
    parser.add_argument("-w", "--secmod_lib", type=str, help="set security module library")
    parser.add_argument("-g", "--gui", help="show GUI", action="store_true")
    parser.add_argument("-l", "--log", help="enable logging", action="store_true")
    parser.add_argument("-f", "--logtofile", help="output log to file", action="store_true")
    parser.add_argument("-lt", "--logtime", help="output the current time in fixed intervals", action="store_true")
    parser.add_argument("-o", "--output", type=str, help="set path for storing of output CSV")
    parser.add_argument("-ob", "--output_bus", type=str, help="set path for storing of bus output CSV")
    parser.add_argument("-p", "--ecu_type", type=str, help="set ECU Type to be used. Valid inputs are lw_auth tls tesla")
    parser.add_argument("-a", "--authenticated", type=str, help="skips ECU authentication when set")
    parser.add_argument("-v", "--variant", type=str, help="variant of execution. possible values: interpreter rapid")
    parser.add_argument("-d", "--arch_con", type=str, help="only for testing purpose: give filepath to file that contains config for ArchConfig")
    args = parser.parse_args()

    args.authenticated = eval(str(args.authenticated))

    # Configurator
    config = ArchConfig(args.arch_con)  # set settings here
    config.config()
    General().print_subversion_info(args)
    SaveRandom(seed)    
    TimingDBMap().enable_fallback_message = True  # show if fallbacks applied
    
    #===========================================================================
    #     Rapid Mode 
    #===========================================================================
    args.variant = config.std_variant(args.variant)
    if args.variant == "rapid" and not args.gui:
        General().diabled_buffer_control = True  # disable buffer control (speedup)
        General().disable_permanent_request = True  # disable permanent request (reduce events)
        if args.ecu_type not in ["tls", "tesla"]: General().send_only_to_receivers = True  # Bus will only send to receivers (speedup)
        show_tags = config.config_rapid_tags()
        path = config.std_path(os.path.dirname(__file__), args.output, "../../logs/checkpoints.csv")        
        General().init_csv_writer(path, show_tags)
        
        GeneralSpecPreset().enable()
        GeneralSpecPreset().datalink_layer = RapidDatalinkLayer
        GeneralSpecPreset().bus = RapidCANBus

    #===========================================================================
    #     Standard values from Parser
    #===========================================================================
    # standard values    
    args.ecu_type = config.std_ecu_type(args.ecu_type)  
    args.authenticated = config.std_authenticated(args.authenticated)
    save_path_cp = config.std_path(os.path.dirname(__file__), args.output, "../../logs/checkpoints.csv")
    save_path_can = config.std_path(os.path.dirname(__file__), args.output_bus, "../../logs/can_bus.csv")
    
    # ecus/ buses/ msgs
    numberOfECUs_max, numberOfECUs_min = config.ecu_numbers(args.ecus_min, args.ecus_max, args.ecus, numberOfECUs_max, numberOfECUs_min)            
    buses_max, buses_min = config.bus_numbers(args.buses_min, args.buses_max, args.buses, buses_min, buses_max)
    msgs_max, msgs_min = config.msg_numbers(args.msgs_min, args.msgs_max, args.msgs, msgs_min, msgs_max)
    
    # values if given
    if args.simtime is not None: simtime = args.simtime
    if args.rcv_buf is not None: receiveBuffer = args.rcv_buf
    if args.snd_buf is not None: sendBuffer = args.snd_buf
    if args.streams_per_ecu is not None: streamPerECU_MAD = args.streams_per_ecu
    if args.receivers_per_stream is not None: receiversPerStreamCoeff = args.receivers_per_stream
    if args.receivers_per_stream_randomize is not None: receiversPerStreamRand = args.receivers_per_stream_randomize
    if args.ecu_lib is not None: ecu_lib = args.ecu_lib
    if args.secmod_lib is not None: sec_mod_lib = args.secmod_lib
    
    # logging  
    config.enable_logging(args.log, args.logtofile)       
                
    #===========================================================================
    #     Pass to ArchGenerator
    #===========================================================================    
    msgPeriodDistr = [[5, 29], [10, 4], [20, 27], [40, 23], [80, 9], [160, 2], [320, 6]]
    msgSizeDistr = [[1, 11], [2, 2], [3, 1], [4, 7], [5, 1], [6, 16], [8, 76], [9, 5], [10, 60], [13, 3], [15, 4], [20, 4], [32, 9]]

    print("generating settings")
    generatorSettings = ArchGeneratorSettings()
    generatorSettings.setECUType(args.ecu_type)
    generatorSettings.setECUBufSizeReceive(receiveBuffer)
    generatorSettings.setECUBufSizeSend(sendBuffer)
    generatorSettings.setMinNumberBuses(buses_min)
    generatorSettings.setMaxNumberBuses(buses_max)
    generatorSettings.setMinNumberECU(numberOfECUs_min)
    generatorSettings.setMaxNumberECU(numberOfECUs_max)
    generatorSettings.setMinNumberMessages(msgs_min)
    generatorSettings.setMaxNumberMessages(msgs_max)
    generatorSettings.setMinMsgID(20)
    generatorSettings.setStreamsPerECUMAD(streamPerECU_MAD)
    generatorSettings.setReceiversPerStreamCoefficient(receiversPerStreamCoeff)
    generatorSettings.setReceiversPerStreamRandomizationFactor(receiversPerStreamRand)
    generatorSettings.setMsgPeriodDistr_ms(msgPeriodDistr)
    generatorSettings.setMsgSizeDistr_byte(msgSizeDistr)
    generatorSettings.setECULibrary(ecu_lib)
    generatorSettings.setSecModLibrary(sec_mod_lib)
    generatorSettings.setAuthenticated(args.authenticated)

    print("creating environment")    
    my_env = api.create_environment(simtime)
    generator = ArchGenerator(my_env)
    print("running generator")
    arch = generator.createArchitecture(generatorSettings)
    print("exporting to API...")
    generator.exportToAPI(arch, api);
    print("export finished")
    
    #===========================================================================
    #     GUI/Interpreter
    #===========================================================================    
    # GUI 
    if args.gui: args.variant = "interpreter"
    
    # Interpreter 
    if args.variant == "interpreter":
        monitor = Monitor()
        monitor.set_sample_time(0.44)
        api.connect_monitor(my_env, monitor, 0.45)  
        my_reader = ResultReader()           
        api.connect_result_reader(my_env, monitor, my_reader)
        config.config_interpreter(my_reader, save_path_cp, save_path_can)        
       
        if args.gui:
            api.connect_result_reader(my_env, monitor, my_reader)            
            direct_view = direct_view_window.DirectViewer()
            my_env.gui_lock_sync.acquire()  # optionally ensure thread synchronization            
            direct_view.run(my_reader, config.config_gui_tags(), my_env.gui_lock_sync)    
            api.open_simulation_stop_button(my_env)
        
    #===========================================================================
    #     Build environment
    #===========================================================================    
    api.build_simulation(my_env)
    api.run_simulation(my_env)

if __name__ == "__main__":
    import sys, getopt
    
    sys.path.append("../../../ECUSimulation")
    sys.path.append("../../../ECUInteraction")
    sys.path.append("../../../Testcases")
    
    import argparse
    import api.ecu_sim_api as api
    from testcases.utilities.archConfig import ArchConfig
    from gui import direct_view_window
    from testcases.utilities.archGenerator import ArchGeneratorSettings, \
        ArchGenerator
    from io_processing.surveillance import Monitor
    from io_processing.result_reader import ResultReader
    from tools.general import General
    from testcases.utilities.archSaver import SaveRandom
    from config.specification_set import GeneralSpecPreset
    from components.base.ecu.software.impl_datalink_layers import RapidDatalinkLayer
    from components.base.bus.impl_rapid_bus_can import RapidCANBus
    from config.timing_db_admin import TimingDBMap
    main(sys.argv[1:])
