# Algoritmo para ler um arquivo pcap de um fluxo e extrair blocos para processar suas features.

# Para UDP calcula apenas A->B = base separada
# extrair blocos_totais (A->B + B->A): 10, 30, 50 pacotes;;; Divisoes: 70%30%,50%50%,30%70%
# extrair blocos_parciais (A->B e B->): 100%0%, 0%100%


## TODO :
# - Quem é o host A e quem é o host B ? (A é o que possui menos pacotes !)
# - Verificar as features que tcptrace calcula para UDP e dizer se vale a pena agregar suas features para gerar a base UDP
# - Como vamos separar os diversos blocos ?
# - Acho que a parte de proporções não faz sentido (50%50%, 70%30%), pois como escolheriamos os pacotes ...

                                        # TCP/UDP
# -- Total (todos os pacotes fazem parte do bloco)
                                        
                                        # PARA TCP
# -- 10 primeiros pacotes do fluxo (considerando A->B e B->A) -> sem considerar subfluxos e considerando subfluxos
# -- 30 primeiros pacotes do fluxo (considerando A->B e B->A) -> sem considerar subfluxos e considerando subfluxos
# -- 50 primeiros pacotes do fluxo (considerando A->B e B->A) -> sem considerar subfluxos e considerando subfluxos


                                        # PARA UDP
# -- 10 primeiros pacotes do fluxo (A->B apenas) -> sem considerar subfluxos e considerando subfluxos
# -- 30 primeiros pacotes do fluxo (A->B apenas) -> sem considerar subfluxos e considerando subfluxos
# -- 50 primeiros pacotes do fluxo (A->B apenas) -> sem considerar subfluxos e considerando subfluxos


import argparse
import os
# import sys

from scapy.utils import PcapReader, PcapNgReader, PcapWriter, wrpcap
from scapy.all import IP, UDP, TCP, Padding, Raw, Ether

from feature_extractor import process_pcap
from ConexaoDB import ConexaoDB

# idle_timeout = 2 #segundos

# Conexao com banco de dados
dbconn = None 



def escrever_resultados(tabela_db, resultados_str, tamanho_bloco):

    
    # print('tabela: ', tabela_db, str(tamanho_bloco))

    #tabelas com diferentes colunas -> twoways_, fluxo_total_two_ways, fluxo_total_ab, ab_
    sql_inserir = resultados_str

    nome_file = ''
    # se for one-way ou UDP -> é outra tabela, tcp outra tabela, fluxos completos_UDP_oneway 
    if 'fluxo_total_two_ways' in tabela_db: # quer dizer fluxo inteiro
        # sql_inserir = """INSERT INTO public.fluxo_total_two_ways(host_a, host_b, a_port, b_port, proto, id_bloco, service_class, app_class, qos_class, qtd_pkts_total, ab_mean_iat_198, ab_med_iat_197, ab_std_iat_201, ab_min_iat_195, ab_max_iat_200, ab_q1_iat_196, ab_q3_iat_199, ab_sum_iat, ab_below_mean_iat, ab_above_mean_iat, ba_mean_iat_205, ba_med_iat_204, ba_std_iat_208, ba_min_iat_202, ba_max_iat_207, ba_q1_iat_203, ba_q3_iat_206, ba_sum_iat, ba_below_mean_iat, ba_above_mean_iat, mean_iat_ref6, med_iat_ref5, min_iat_ref3, q1_iat_ref4, q3_iat_ref3, max_iat_ref8, std_iat_ref9, sum_iat, below_mean_iat, above_mean_iat, no_transitions_bulktrans_210, time_spent_in_bulk_211, duration_connection_duration_212, bulk_percent_of_time_spent_213, time_spent_idle_214, idle_percent_of_time_215, ab_bytes_per_sec, ab_mean_data_control_163, ab_med_data_control_162, ab_var_data_control_166, ab_min_data_control_160, ab_max_data_control_165, ab_q1_data_control_161, ab_q3_data_control_164, ab_mean_data_ip_163, ab_med_data_ip_162, ab_var_data_ip_166, ab_min_data_ip_160, ab_max_data_ip_165, ab_q1_data_ip_161, ab_q3_data_ip_164, ab_min_data_control_307, ab_q1_data_control_308, ab_med_data_control_309, ab_mean_data_control_310, ab_q3_data_control_311, ab_max_data_control_312, ab_var_data_control_313, ab_mean_data_pkt_156, ab_med_data_pkt_155, ab_var_data_pkt_159, ab_min_data_pkt_153, ab_max_data_pkt_158, ab_q1_data_pkt_154, ab_q3_data_pkt_157, ab_mean_header_ip_ref321, ab_med_header_ip_ref322, ab_std_header_ip_ref323, ab_min_header_ip_ref324, ab_max_header_ip_ref325, ab_q1_header_ip_ref326, ab_q3_header_ip_ref327, ab_pkts_abv_1024, ab_pays_bel_128, ab_pays_in_128_1024, ab_pkts_abv_mean, ab_pkts_bel_mean, ab_pkts_header_sum, ab_pkts_len_sum, ab_pkts_per_sec, ba_bytes_per_sec, ba_mean_data_control_184, ba_med_data_control_183, ba_var_data_control_187, ba_min_data_control_181, ba_max_data_control_186, ba_q1_data_control_182, ba_q3_data_control_185, ba_mean_data_ip_184, ba_med_data_ip_183, ba_var_data_ip_187, ba_min_data_ip_181, ba_max_data_ip_186, ba_q1_data_ip_182, ba_q3_data_ip_185, ba_min_data_control_314, ba_q1_data_control_315, ba_med_data_control_316, ba_mean_data_control_317, ba_q3_data_control_318, ba_max_data_control_319, ba_var_data_control_320, ba_mean_data_pkt_177, ba_med_data_pkt_176, ba_var_data_pkt_180, ba_min_data_pkt_174, ba_max_data_pkt_179, ba_q1_data_pkt_175, ba_q3_data_pkt_178, ba_mean_header_ip_ref191, ba_med_header_ip_ref190, ba_std_header_ip_ref194, ba_min_header_ip_ref188, ba_max_header_ip_ref193, ba_q1_header_ip_ref189, ba_q3_header_ip_ref192, ba_pays_abv_1024, ba_pays_bel_128, ba_pays_in_128_1024, ba_pkts_abv_mean, ba_pkts_bel_mean, ba_pkts_header_sum, ba_pkts_len_sum, ba_pkts_per_sec, bytes_per_sec, mean_data_control_ref27, med_data_control_ref26, std_data_control_ref30, min_data_control_ref24, max_data_control_ref29, q1_data_control_ref25, q3_data_control_ref28, mean_data_ip_ref20, med_data_ip_ref19, std_data_ip_ref23, min_data_ip_ref17, max_data_ip_ref22, q1_data_ip_ref18, q3_data_ip_ref21, mean_data_payload_ref300, med_data_payload_ref301, std_data_payload_ref302, min_data_payload_ref303, max_data_payload_ref304, q1_data_payload_ref305, q3_data_payload_ref306, mean_data_pkt_ref13, med_data_pkt_ref12, std_data_pkt_ref16, min_data_pkt_ref10, max_data_pkt_ref15, q1_data_pkt_ref11, q3_data_pkt_ref14, mean_header_ip_ref27, med_header_ip_ref26, std_header_ip_ref30, min_header_ip_ref24, max_header_ip_ref29, q1_header_ip_ref25, q3_header_ip_ref28, pays_abv_1024, pays_bel_128, pays_in_128_1024, pkts_abv_mean, pkts_bel_mean, pkts_header_sum, pkts_len_sum, pkts_per_sec, first_packet, last_packet, total_packets_a2b, total_packets_b2a, resets_sent_a2b, resets_sent_b2a, ack_pkts_sent_a2b, ack_pkts_sent_b2a, pure_acks_sent_a2b, pure_acks_sent_b2a, sack_pkts_sent_a2b, sack_pkts_sent_b2a, dsack_pkts_sent_a2b, dsack_pkts_sent_b2a, max_sack_blkslack_a2b, max_sack_blkslack_b2a, unique_bytes_sent_a2b, unique_bytes_sent_b2a, actual_data_pkts_a2b, actual_data_pkts_b2a, actual_data_bytes_a2b, actual_data_bytes_b2a, rexmt_data_pkts_a2b, rexmt_data_pkts_b2a, rexmt_data_bytes_a2b, rexmt_data_bytes_b2a, zwnd_probe_pkts_a2b, zwnd_probe_pkts_b2a, zwnd_probe_bytes_a2b, zwnd_probe_bytes_b2a, outoforder_pkts_a2b, outoforder_pkts_b2a, pushed_data_pkts_a2b, pushed_data_pkts_b2a, synlfin_pkts_sent_a2b, synlfin_pkts_sent_b2a, req_1323_wslts_a2b, req_1323_wslts_b2a, adv_wind_scale_a2b, adv_wind_scale_b2a, req_sack_a2b, req_sack_b2a, sacks_sent_a2b, sacks_sent_b2a, urgent_data_pkts_a2b, urgent_data_pkts_b2a, urgent_data_bytes_a2b, urgent_data_bytes_b2a, mss_requested_a2b, mss_requested_b2a, max_segm_size_a2b, max_segm_size_b2a, min_segm_size_a2b, min_segm_size_b2a, avg_segm_size_a2b, avg_segm_size_b2a, max_win_adv_a2b, max_win_adv_b2a, min_win_adv_a2b, min_win_adv_b2a, zero_win_adv_a2b, zero_win_adv_b2a, avg_win_adv_a2b, avg_win_adv_b2a, max_owin_a2b, max_owin_b2a, min_nonzero_owin_a2b, min_nonzero_owin_b2a, avg_owin_a2b, avg_owin_b2a, wavg_owin_a2b, wavg_owin_b2a, initial_window_bytes_a2b, initial_window_bytes_b2a, initial_window_pkts_a2b, initial_window_pkts_b2a, ttl_stream_length_a2b, ttl_stream_length_b2a, missed_data_a2b, missed_data_b2a, truncated_data_a2b, truncated_data_b2a, truncated_packets_a2b, truncated_packets_b2a, data_xmit_time_a2b, data_xmit_time_b2a, idletime_max_a2b, idletime_max_b2a, hardware_dups_a2b, hardware_dups_b2a, throughput_a2b, throughput_b2a, rtt_samples_a2b, rtt_samples_b2a, rtt_min_a2b, rtt_min_b2a, rtt_max_a2b, rtt_max_b2a, rtt_avg_a2b, rtt_avg_b2a, rtt_stdev_a2b, rtt_stdev_b2a, rtt_from_3whs_a2b, rtt_from_3whs_b2a, rtt_full_sz_smpls_a2b, rtt_full_sz_smpls_b2a, rtt_full_sz_min_a2b, rtt_full_sz_min_b2a, rtt_full_sz_max_a2b, rtt_full_sz_max_b2a, rtt_full_sz_avg_a2b, rtt_full_sz_avg_b2a, rttfull_sz_stdev_a2b, rtt_full_sz_stdev_b2a, postloss_acks_a2b, postloss_acks_b2a, ambiguous_acks_a2b, ambiguous_acks_b2a, rtt_min_last_a2b, rtt_min_last_b2a, rtt_max_last_a2b, rtt_max_last_b2a, rtt_avg_last_a2b, rtt_avg_last_b2a, rtt_sdv_last_a2b, rtt_sdv_last_b2a, segs_cum_acked_a2b, segs_cum_acked_b2a, duplicate_acks_a2b, duplicate_acks_b2a, triple_dupacks_a2b, triple_dupacks_b2a, max_retrans_a2b, max_retrans_b2a, min_retr_time_a2b, min_retr_time_b2a, max_retr_time_a2b, max_retr_time_b2a, avg_retr_time_a2b, avg_retr_time_b2a, sdv_retr_time_a2b, sdv_retr_time_b2a) VALUES ({});""".format(resultados_str)
        nome_file = 'fluxo_total_two_ways'
        # salvar a saida no banco de dados
    elif 'twoways_' in tabela_db:
        # varia tbm bloco IAT fixo
        # sql_inserir = """INSERT INTO public.twoways_{}pkts_2s(host_a, host_b, a_port, b_port, proto, id_bloco, service_class, app_class, qos_class, qtd_pkts_total, ab_mean_iat_198, ab_med_iat_197, ab_std_iat_201, ab_min_iat_195, ab_max_iat_200, ab_q1_iat_196, ab_q3_iat_199, ab_sum_iat, ab_below_mean_iat, ab_above_mean_iat, ba_mean_iat_205, ba_med_iat_204, ba_std_iat_208, ba_min_iat_202, ba_max_iat_207, ba_q1_iat_203, ba_q3_iat_206, ba_sum_iat, ba_below_mean_iat, ba_above_mean_iat, mean_iat_ref6, med_iat_ref5, min_iat_ref3, q1_iat_ref4, q3_iat_ref3, max_iat_ref8, std_iat_ref9, sum_iat, below_mean_iat, above_mean_iat, no_transitions_bulktrans_210, time_spent_in_bulk_211, duration_connection_duration_212, bulk_percent_of_time_spent_213, time_spent_idle_214, idle_percent_of_time_215, ab_bytes_per_sec, ab_mean_data_control_163, ab_med_data_control_162, ab_var_data_control_166, ab_min_data_control_160, ab_max_data_control_165, ab_q1_data_control_161, ab_q3_data_control_164, ab_mean_data_ip_163, ab_med_data_ip_162, ab_var_data_ip_166, ab_min_data_ip_160, ab_max_data_ip_165, ab_q1_data_ip_161, ab_q3_data_ip_164, ab_min_data_control_307, ab_q1_data_control_308, ab_med_data_control_309, ab_mean_data_control_310, ab_q3_data_control_311, ab_max_data_control_312, ab_var_data_control_313, ab_mean_data_pkt_156, ab_med_data_pkt_155, ab_var_data_pkt_159, ab_min_data_pkt_153, ab_max_data_pkt_158, ab_q1_data_pkt_154, ab_q3_data_pkt_157, ab_mean_header_ip_ref321, ab_med_header_ip_ref322, ab_std_header_ip_ref323, ab_min_header_ip_ref324, ab_max_header_ip_ref325, ab_q1_header_ip_ref326, ab_q3_header_ip_ref327, ab_pkts_abv_1024, ab_pays_bel_128, ab_pays_in_128_1024, ab_pkts_abv_mean, ab_pkts_bel_mean, ab_pkts_header_sum, ab_pkts_len_sum, ab_pkts_per_sec, ba_bytes_per_sec, ba_mean_data_control_184, ba_med_data_control_183, ba_var_data_control_187, ba_min_data_control_181, ba_max_data_control_186, ba_q1_data_control_182, ba_q3_data_control_185, ba_mean_data_ip_184, ba_med_data_ip_183, ba_var_data_ip_187, ba_min_data_ip_181, ba_max_data_ip_186, ba_q1_data_ip_182, ba_q3_data_ip_185, ba_min_data_control_314, ba_q1_data_control_315, ba_med_data_control_316, ba_mean_data_control_317, ba_q3_data_control_318, ba_max_data_control_319, ba_var_data_control_320, ba_mean_data_pkt_177, ba_med_data_pkt_176, ba_var_data_pkt_180, ba_min_data_pkt_174, ba_max_data_pkt_179, ba_q1_data_pkt_175, ba_q3_data_pkt_178, ba_mean_header_ip_ref191, ba_med_header_ip_ref190, ba_std_header_ip_ref194, ba_min_header_ip_ref188, ba_max_header_ip_ref193, ba_q1_header_ip_ref189, ba_q3_header_ip_ref192, ba_pays_abv_1024, ba_pays_bel_128, ba_pays_in_128_1024, ba_pkts_abv_mean, ba_pkts_bel_mean, ba_pkts_header_sum, ba_pkts_len_sum, ba_pkts_per_sec, bytes_per_sec, mean_data_control_ref27, med_data_control_ref26, std_data_control_ref30, min_data_control_ref24, max_data_control_ref29, q1_data_control_ref25, q3_data_control_ref28, mean_data_ip_ref20, med_data_ip_ref19, std_data_ip_ref23, min_data_ip_ref17, max_data_ip_ref22, q1_data_ip_ref18, q3_data_ip_ref21, mean_data_payload_ref300, med_data_payload_ref301, std_data_payload_ref302, min_data_payload_ref303, max_data_payload_ref304, q1_data_payload_ref305, q3_data_payload_ref306, mean_data_pkt_ref13, med_data_pkt_ref12, std_data_pkt_ref16, min_data_pkt_ref10, max_data_pkt_ref15, q1_data_pkt_ref11, q3_data_pkt_ref14, mean_header_ip_ref27, med_header_ip_ref26, std_header_ip_ref30, min_header_ip_ref24, max_header_ip_ref29, q1_header_ip_ref25, q3_header_ip_ref28, pays_abv_1024, pays_bel_128, pays_in_128_1024, pkts_abv_mean, pkts_bel_mean, pkts_header_sum, pkts_len_sum, pkts_per_sec, first_packet, last_packet, total_packets_a2b, total_packets_b2a, resets_sent_a2b, resets_sent_b2a, ack_pkts_sent_a2b, ack_pkts_sent_b2a, pure_acks_sent_a2b, pure_acks_sent_b2a, sack_pkts_sent_a2b, sack_pkts_sent_b2a, dsack_pkts_sent_a2b, dsack_pkts_sent_b2a, max_sack_blkslack_a2b, max_sack_blkslack_b2a, unique_bytes_sent_a2b, unique_bytes_sent_b2a, actual_data_pkts_a2b, actual_data_pkts_b2a, actual_data_bytes_a2b, actual_data_bytes_b2a, rexmt_data_pkts_a2b, rexmt_data_pkts_b2a, rexmt_data_bytes_a2b, rexmt_data_bytes_b2a, zwnd_probe_pkts_a2b, zwnd_probe_pkts_b2a, zwnd_probe_bytes_a2b, zwnd_probe_bytes_b2a, outoforder_pkts_a2b, outoforder_pkts_b2a, pushed_data_pkts_a2b, pushed_data_pkts_b2a, synlfin_pkts_sent_a2b, synlfin_pkts_sent_b2a, req_1323_wslts_a2b, req_1323_wslts_b2a, adv_wind_scale_a2b, adv_wind_scale_b2a, req_sack_a2b, req_sack_b2a, sacks_sent_a2b, sacks_sent_b2a, urgent_data_pkts_a2b, urgent_data_pkts_b2a, urgent_data_bytes_a2b, urgent_data_bytes_b2a, mss_requested_a2b, mss_requested_b2a, max_segm_size_a2b, max_segm_size_b2a, min_segm_size_a2b, min_segm_size_b2a, avg_segm_size_a2b, avg_segm_size_b2a, max_win_adv_a2b, max_win_adv_b2a, min_win_adv_a2b, min_win_adv_b2a, zero_win_adv_a2b, zero_win_adv_b2a, avg_win_adv_a2b, avg_win_adv_b2a, max_owin_a2b, max_owin_b2a, min_nonzero_owin_a2b, min_nonzero_owin_b2a, avg_owin_a2b, avg_owin_b2a, wavg_owin_a2b, wavg_owin_b2a, initial_window_bytes_a2b, initial_window_bytes_b2a, initial_window_pkts_a2b, initial_window_pkts_b2a, ttl_stream_length_a2b, ttl_stream_length_b2a, missed_data_a2b, missed_data_b2a, truncated_data_a2b, truncated_data_b2a, truncated_packets_a2b, truncated_packets_b2a, data_xmit_time_a2b, data_xmit_time_b2a, idletime_max_a2b, idletime_max_b2a, hardware_dups_a2b, hardware_dups_b2a, throughput_a2b, throughput_b2a, rtt_samples_a2b, rtt_samples_b2a, rtt_min_a2b, rtt_min_b2a, rtt_max_a2b, rtt_max_b2a, rtt_avg_a2b, rtt_avg_b2a, rtt_stdev_a2b, rtt_stdev_b2a, rtt_from_3whs_a2b, rtt_from_3whs_b2a, rtt_full_sz_smpls_a2b, rtt_full_sz_smpls_b2a, rtt_full_sz_min_a2b, rtt_full_sz_min_b2a, rtt_full_sz_max_a2b, rtt_full_sz_max_b2a, rtt_full_sz_avg_a2b, rtt_full_sz_avg_b2a, rttfull_sz_stdev_a2b, rtt_full_sz_stdev_b2a, postloss_acks_a2b, postloss_acks_b2a, ambiguous_acks_a2b, ambiguous_acks_b2a, rtt_min_last_a2b, rtt_min_last_b2a, rtt_max_last_a2b, rtt_max_last_b2a, rtt_avg_last_a2b, rtt_avg_last_b2a, rtt_sdv_last_a2b, rtt_sdv_last_b2a, segs_cum_acked_a2b, segs_cum_acked_b2a, duplicate_acks_a2b, duplicate_acks_b2a, triple_dupacks_a2b, triple_dupacks_b2a, max_retrans_a2b, max_retrans_b2a, min_retr_time_a2b, min_retr_time_b2a, max_retr_time_a2b, max_retr_time_b2a, avg_retr_time_a2b, avg_retr_time_b2a, sdv_retr_time_a2b, sdv_retr_time_b2a) VALUES ({});""".format(str(tamanho_bloco),resultados_str)
        nome_file = 'twoways_%spkts_2s' % (str(tamanho_bloco))
    elif 'fluxo_total_ab' in tabela_db: # one way TCP
        # sql_inserir = """INSERT INTO public.fluxo_total_ab(host_a, host_b, a_port, b_port, proto, id_bloco, service_class, app_class, qos_class, qtd_pkts_total, ab_mean_iat_198, ab_med_iat_197, ab_std_iat_201, ab_min_iat_195, ab_max_iat_200, ab_q1_iat_196, ab_q3_iat_199, ab_sum_iat, ab_below_mean_iat, ab_above_mean_iat, no_transitions_bulktrans_210, time_spent_in_bulk_211, duration_connection_duration_212, bulk_percent_of_time_spent_213, time_spent_idle_214, idle_percent_of_time_215, ab_bytes_per_sec, ab_mean_data_control_163, ab_med_data_control_162, ab_var_data_control_166, ab_min_data_control_160, ab_max_data_control_165, ab_q1_data_control_161, ab_q3_data_control_164, ab_mean_data_ip_163, ab_med_data_ip_162, ab_var_data_ip_166, ab_min_data_ip_160, ab_max_data_ip_165, ab_q1_data_ip_161, ab_q3_data_ip_164, ab_min_data_control_307, ab_q1_data_control_308, ab_med_data_control_309, ab_mean_data_control_310, ab_q3_data_control_311, ab_max_data_control_312, ab_var_data_control_313, ab_mean_data_pkt_156, ab_med_data_pkt_155, ab_var_data_pkt_159, ab_min_data_pkt_153, ab_max_data_pkt_158, ab_q1_data_pkt_154, ab_q3_data_pkt_157, ab_mean_header_ip_ref321, ab_med_header_ip_ref322, ab_std_header_ip_ref323, ab_min_header_ip_ref324, ab_max_header_ip_ref325, ab_q1_header_ip_ref326, ab_q3_header_ip_ref327, ab_pkts_abv_1024, ab_pays_bel_128, ab_pays_in_128_1024, ab_pkts_abv_mean, ab_pkts_bel_mean, ab_pkts_header_sum, ab_pkts_len_sum, ab_pkts_per_sec) VALUES ({});""".format(resultados_str)
        # print('aqui')
        nome_file = 'fluxo_total_ab'
    elif 'ab_tcp_' in tabela_db:    
        # sql_inserir = """INSERT INTO public.ab_tcp_{}pkts_2s(host_a, host_b, a_port, b_port, proto, id_bloco, service_class, app_class, qos_class, qtd_pkts_total, ab_mean_iat_198, ab_med_iat_197, ab_std_iat_201, ab_min_iat_195, ab_max_iat_200, ab_q1_iat_196, ab_q3_iat_199, ab_sum_iat, ab_below_mean_iat, ab_above_mean_iat, no_transitions_bulktrans_210, time_spent_in_bulk_211, duration_connection_duration_212, bulk_percent_of_time_spent_213, time_spent_idle_214, idle_percent_of_time_215, ab_bytes_per_sec, ab_mean_data_control_163, ab_med_data_control_162, ab_var_data_control_166, ab_min_data_control_160, ab_max_data_control_165, ab_q1_data_control_161, ab_q3_data_control_164, ab_mean_data_ip_163, ab_med_data_ip_162, ab_var_data_ip_166, ab_min_data_ip_160, ab_max_data_ip_165, ab_q1_data_ip_161, ab_q3_data_ip_164, ab_min_data_control_307, ab_q1_data_control_308, ab_med_data_control_309, ab_mean_data_control_310, ab_q3_data_control_311, ab_max_data_control_312, ab_var_data_control_313, ab_mean_data_pkt_156, ab_med_data_pkt_155, ab_var_data_pkt_159, ab_min_data_pkt_153, ab_max_data_pkt_158, ab_q1_data_pkt_154, ab_q3_data_pkt_157, ab_mean_header_ip_ref321, ab_med_header_ip_ref322, ab_std_header_ip_ref323, ab_min_header_ip_ref324, ab_max_header_ip_ref325, ab_q1_header_ip_ref326, ab_q3_header_ip_ref327, ab_pkts_abv_1024, ab_pays_bel_128, ab_pays_in_128_1024, ab_pkts_abv_mean, ab_pkts_bel_mean, ab_pkts_header_sum, ab_pkts_len_sum, ab_pkts_per_sec, first_packet, last_packet, total_packets_a2b, resets_sent_a2b, ack_pkts_sent_a2b, pure_acks_sent_a2b, sack_pkts_sent_a2b, dsack_pkts_sent_a2b, max_sack_blkslack_a2b, unique_bytes_sent_a2b, actual_data_pkts_a2b, actual_data_bytes_a2b, rexmt_data_pkts_a2b, rexmt_data_bytes_a2b, zwnd_probe_pkts_a2b, zwnd_probe_bytes_a2b, outoforder_pkts_a2b, pushed_data_pkts_a2b, synlfin_pkts_sent_a2b, req_1323_wslts_a2b, adv_wind_scale_a2b, req_sack_a2b, sacks_sent_a2b, urgent_data_pkts_a2b, urgent_data_bytes_a2b, mss_requested_a2b, max_segm_size_a2b, min_segm_size_a2b, avg_segm_size_a2b, max_win_adv_a2b, min_win_adv_a2b, zero_win_adv_a2b, avg_win_adv_a2b, max_owin_a2b, min_nonzero_owin_a2b, avg_owin_a2b, wavg_owin_a2b, initial_window_bytes_a2b, initial_window_pkts_a2b, ttl_stream_length_a2b, missed_data_a2b, truncated_data_a2b, truncated_packets_a2b, data_xmit_time_a2b, idletime_max_a2b, hardware_dups_a2b, throughput_a2b, rtt_samples_a2b, rtt_min_a2b, rtt_max_a2b, rtt_avg_a2b, rtt_stdev_a2b, rtt_from_3whs_a2b, rtt_full_sz_smpls_a2b, rtt_full_sz_min_a2b, rtt_full_sz_max_a2b, rtt_full_sz_avg_a2b, rttfull_sz_stdev_a2b, postloss_acks_a2b, ambiguous_acks_a2b, rtt_min_last_a2b, rtt_max_last_a2b, rtt_avg_last_a2b, rtt_sdv_last_a2b, segs_cum_acked_a2b, duplicate_acks_a2b, triple_dupacks_a2b, max_retrans_a2b, min_retr_time_a2b, max_retr_time_a2b, avg_retr_time_a2b, sdv_retr_time_a2b) VALUES ({});""".format(str(tamanho_bloco),resultados_str)
        nome_file = 'ab_tcp_%spkts_2s' % (str(tamanho_bloco))
    else: # one way UDP --> ab_
        # sql_inserir = """INSERT INTO public.ab_{}pkts_2s(host_a, host_b, a_port, b_port, proto, id_bloco, service_class, app_class, qos_class, qtd_pkts_total, ab_mean_iat_198, ab_med_iat_197, ab_std_iat_201, ab_min_iat_195, ab_max_iat_200, ab_q1_iat_196, ab_q3_iat_199, ab_sum_iat, ab_below_mean_iat, ab_above_mean_iat, no_transitions_bulktrans_210, time_spent_in_bulk_211, duration_connection_duration_212, bulk_percent_of_time_spent_213, time_spent_idle_214, idle_percent_of_time_215, ab_bytes_per_sec, ab_mean_data_control_163, ab_med_data_control_162, ab_var_data_control_166, ab_min_data_control_160, ab_max_data_control_165, ab_q1_data_control_161, ab_q3_data_control_164, ab_mean_data_ip_163, ab_med_data_ip_162, ab_var_data_ip_166, ab_min_data_ip_160, ab_max_data_ip_165, ab_q1_data_ip_161, ab_q3_data_ip_164, ab_min_data_control_307, ab_q1_data_control_308, ab_med_data_control_309, ab_mean_data_control_310, ab_q3_data_control_311, ab_max_data_control_312, ab_var_data_control_313, ab_mean_data_pkt_156, ab_med_data_pkt_155, ab_var_data_pkt_159, ab_min_data_pkt_153, ab_max_data_pkt_158, ab_q1_data_pkt_154, ab_q3_data_pkt_157, ab_mean_header_ip_ref321, ab_med_header_ip_ref322, ab_std_header_ip_ref323, ab_min_header_ip_ref324, ab_max_header_ip_ref325, ab_q1_header_ip_ref326, ab_q3_header_ip_ref327, ab_pkts_abv_1024, ab_pays_bel_128, ab_pays_in_128_1024, ab_pkts_abv_mean, ab_pkts_bel_mean, ab_pkts_header_sum, ab_pkts_len_sum, ab_pkts_per_sec) VALUES ({});""".format(str(tamanho_bloco),resultados_str)
        nome_file = 'ab_%spkts_2s' % (str(tamanho_bloco))
    
    # print(tabela_db, ' ][ ', len(resultado_colunas))
    # print(sql_inserir)
    file = open(nome_file, 'a')
    file.write(sql_inserir+'\n')
    file.close()
    



def criar_pcaps_aux_one_way_ab_e_ba(nome_arquivo):

    host_a = None

    leitor = PcapReader

    pacotes_ab = []
    pacotes_ba = []

    if 'pcapng' in nome_arquivo:
        leitor = PcapNgReader


    with leitor(nome_arquivo) as reader:
        for pkt in reader:
            if host_a == None:
                host_a = pkt[IP].src

            if pkt[IP].src == host_a:
                pacotes_ab.append(pkt)
            else:
                pacotes_ba.append(pkt)

    if pacotes_ab != []:
            
        _linktype = 101 # raw_ip

        if pacotes_ab[0].haslayer(Ether):
            _linktype = 1 # ethernet

        # wrpcap("ab.pcap", pacotes_ab, append=False, linktype = _linktype)
        pktdump = PcapWriter("ab.pcap", append=False, linktype = _linktype) # mais rapido que wrpcap pois permite flush
        pktdump.write(pacotes_ab)
        pktdump.flush()
        
    if pacotes_ba != []:
        _linktype = 101 # raw_ip

        if pacotes_ba[0].haslayer(Ether):
            _linktype = 1 # ethernet

        # wrpcap("ba.pcap", pacotes_ba, append=False, linktype = _linktype)
        pktdump = PcapWriter("ba.pcap", append=False, linktype = _linktype)
        pktdump.write(pacotes_ba)
        pktdump.flush()

def gerar_blocos_processar(file_name, tabela_db, proto, service_class, app_class, qos_class, tcptrace=True, host_a= None, two_way= True, debug=False, block_size_max =None, block_size_min=0, idle_timeout=None):
    """ Gera blocos de pacotes e processa:
        file_name = nome do arquivo pcap do fluxo
        app_label = qual rótulo desse fluxo, se for conhecido (fase de treinamento).
        block_size = tamanho de cada bloco (0 == fluxo inteiro)
        subflows = IAT considerado de um subflow (None == nao considerar)
        two_ways = True or false
        ip_a = decidir manualmente quem é o IP ou deixar None e escolher sempre o que tiver mais pacotes como sendo o host_A (obs: isso é definido no primeiro bloco)
    """
    if not os.path.exists(file_name):
        print('->',file_name,' não existe')
        return
    
    print('Opening {} sz: {} tam_bloco: {} tabela: {}...'.format(file_name, os.path.getsize(file_name), block_size_min, tabela_db))
    
    if os.path.getsize(file_name) < 100: # arquivo maior que 1kb
        print("[Diss] Arquivo vazio !")
        return 
    
    blocos_processados = 0    
    tamanho_bloco = 0
    contador_pacotes = 0

    leitor = PcapReader

    if 'pcapng' in file_name:
        leitor = PcapNgReader

    bloco_pacotes = []

    limite_bloco = 100000 #? definir um limite para não estourar a memória?
    min_bloco = block_size_min

    if block_size_max != None:
        limite_bloco = block_size_max

    if idle_timeout == None:
        idle_timeout = 9999999

    timestamp_prev = None

    # processar bloco total
    try:
        for pkt in leitor(file_name):
            # consideramos que todos os pacotes são IP

            # keep alive...
            if contador_pacotes % 5000 == 0:
                print('[working] pacotes_processados {} blocos processados {} pacotes bloco atuaal {}'.format(contador_pacotes, blocos_processados, tamanho_bloco))

            if timestamp_prev == None:
                timestamp_prev = float(pkt.time)

            if (float(pkt.time) - timestamp_prev > idle_timeout) or (tamanho_bloco >= limite_bloco):

                # mas, se o bloco tiver mais pacotes que o mínimo estabelecido, então calcular as features desse bloco
                #definir quem é o ip_a (host_a) -- só se faz uma vez e vale para todo o fluxo
                if tamanho_bloco >= min_bloco:
                    # if host_a == None: 
                    host_a = host_mais_pacotes(bloco_pacotes=bloco_pacotes)
                    
                    blocos_processados += 1
                    processar(tamanho_bloco, blocos_processados, host_a, proto, service_class, app_class, qos_class, bloco_pacotes, tabela_db, two_way, tcptrace, debug)
                    
                bloco_pacotes.clear()
                tamanho_bloco = 0

            bloco_pacotes.append(pkt)
            tamanho_bloco+=1
            contador_pacotes += 1      

            timestamp_prev = float(pkt.time)
    except:
        print('[fail] Arquivo vazio {}'.format(file_name))
        return
    
    if tamanho_bloco >= min_bloco:
        #definir quem é o ip_a (host_a) -- só se faz uma vez e vale para todo o fluxo
        host_a = host_mais_pacotes(bloco_pacotes=bloco_pacotes)

        blocos_processados += 1
        # print('pacotes_processados {} contadorblock {} iteracao de processamento {}'.format(contador_pacotes, tamanho_bloco, blocos_processados))
        processar(tamanho_bloco, blocos_processados, host_a, proto, service_class, app_class, qos_class, bloco_pacotes, tabela_db, two_way, tcptrace, debug)
        
    bloco_pacotes.clear()

    print("file: ",file_name," finished !")


def processar(tamanho_bloco, id_bloco, host_a, proto, service_class, app_class, qos_class, bloco_pacotes, tabela_db, two_ways, tcptrace, debug):

    # daqui pra frente está indo errado os blocoso
    _linktype = 101 # raw_ip

    if bloco_pacotes[0].haslayer(Ether):
        _linktype = 1 # ethernet

    #criar arquivo aux.pcap -- OBS: # linktype dos pcap são importantes para serem interpretados pelo tcptrace (aparentemente linktype 228 não tem suporte no tcptrace)
    # wrpcap("aux.pcap", bloco_pacotes, append=False, linktype = _linktype)

    if os.path.exists('aux.pcap'):
        os.remove('aux.pcap')
    pktdump = PcapWriter("aux.pcap", append=False, linktype = _linktype) # mais rapido que wrpcap pois permite flush
    pktdump.write(bloco_pacotes)
    pktdump.flush()

    # processar arquivo aux
    resultado_saida, resultado_colunas = process_pcap(id_bloco =id_bloco, host_a =host_a, proto=proto, service_class=service_class, app_class=app_class, qos_class=qos_class, entrada_arquivo_pcap='aux.pcap', two_way=two_ways, tcptrace=tcptrace, debug=debug)

    resultados_str = ""

    for val in resultado_saida:
        resultados_str+= ",'"+str(val)+"'"

    resultados_str = resultados_str.removeprefix(',')

    escrever_resultados(tabela_db, resultados_str, tamanho_bloco)

    if debug:
        print('tam = ', len(bloco_pacotes))
        print('resultados: ', len(resultado_saida), ' - colunas: ', len(resultado_colunas))
        for i in range(0, len(resultado_saida)):
            print('[',i,']', resultado_colunas[i], ' : ', resultado_saida[i])
    
    return 

def host_mais_pacotes(bloco_pacotes):
    """ Entrada: bloco de pacotes
        Saída: ip do host que tiver mais pacotes no bloco"""
    
    # teste de sanidade
    if not bloco_pacotes:
        return ''
    
    host_a = bloco_pacotes[0][IP].src
    host_b = bloco_pacotes[0][IP].dst
    contador = 0
    for pkt in bloco_pacotes:
        if pkt[IP].src == host_a:
            contador+=1
        else:
            contador-=1
    
    if contador > 0:
        return host_a
    
    return host_b

if __name__ == '__main__':

    # print("conectando com DB")
    # dbconn = ConexaoDB(mhost='localhost', db='featuresdb', usr='postgres', pwd='214336414')

    # if dbconn:
    #     print("DB conectado !")
    # else:
    #     print("DB não conectado !")
    #     exit(0)

    parser = argparse.ArgumentParser(description='estatistica fluxos')
    parser.add_argument('--service_class', metavar='<[string] class of service (ex. video_real)>',
                        help='<[string] class of service (ex. video_real)>', required=True)
    parser.add_argument('--app_class', metavar='<[string] app of service (ex. facebook)>',
                        help='<[string] app of service (ex. facebook)>', required=True)
    parser.add_argument('--qos_class', metavar='<[string] qos  of service (ex. 360p)>',
                        help='<[string] qos of service (ex. 360pk)>', required=True)
    parser.add_argument('--folder_name', metavar='<[string] folder of the captured flows (pcap or pcapng)>',
                        help='<[string] folder of the captured flows (pcap or pcapng)>', required=True)
    
    args = parser.parse_args()

    # file_name = '/mnt/7A2C27352C26EC37/artigo_traffic_classification2/bases_raw/flow_total_facebook_audio2a__TCP_173.252.100.27_131.202.240.150_443_56404.pcap'
    # file_name = '/mnt/7A2C27352C26EC37/artigo_traffic_classification2/bases_raw/flow_total_facebook_video1a__UDP_131.202.240.87_131.202.240.150_51706_58046.pcap'
    
    try:
        os.remove('ab.pcap')
        os.remove('ba.pcap')
        os.remove('db_inserts.dat')
    except:
        print('[arquivos prov anteriores removidos]')    


    folder_name = args.folder_name
    lista_arquivos = os.listdir(folder_name)

    service_class = args.service_class
    app_class = args.app_class
    qos_class = args.qos_class

    for file_name in lista_arquivos:
        if '.pcap' not in file_name:
            continue

        file_name = folder_name + file_name

        proto = None
        if 'TCP' in file_name:
            proto = 'TCP'
        elif 'UDP' in file_name:
            proto = 'UDP'
        else: 
            continue
        
        print("[inicio]:", file_name)

        try:
            os.remove('ab.pcap')
            os.remove('ba.pcap')
            os.remove('db_inserts.dat')
        except:
            print('[sem arquivos anteriores]')    

        print('criar arquivos ab')
        # criar arquivos one_way
        criar_pcaps_aux_one_way_ab_e_ba(file_name) 

        #tabelas -> twoways_, fluxo_total_two_ways, fluxo_total_ab, ab_
        print("gerando blocos e processando")
        # Calcular o fluxo total    ################################################################
        # print('calculando fluxo_total_ab e ba')
        #ab
        saida = gerar_blocos_processar(file_name= 'ab.pcap', tabela_db='fluxo_total_ab', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez utilizar esses depois
        #ba
        saida = gerar_blocos_processar(file_name= 'ba.pcap', tabela_db='fluxo_total_ab', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez utilizar esses depois
        ##############################################################################################

        # print('calculando ab_10pkts_2s')
        # 10 pacotes IAT 2s         ##################################################################
        #ab
        saida = gerar_blocos_processar(block_size_max=10, block_size_min=10, file_name= 'ab.pcap', tabela_db='ab_10pkts_2s', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
        #ba
        saida = gerar_blocos_processar(block_size_max=10, block_size_min=10, file_name= 'ba.pcap', tabela_db='ab_10pkts_2s', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
        ##############################################################################################

        # print('calculando ab_30pkts_2')
        # 30 pacotes IAT 2s         ##################################################################
        #ab
        saida = gerar_blocos_processar(block_size_max=30, block_size_min=30, file_name= 'ab.pcap', tabela_db='ab_30pkts_2s', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
        #ba
        saida = gerar_blocos_processar(block_size_max=30, block_size_min=30, file_name= 'ba.pcap', tabela_db='ab_30pkts_2s', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
        ##############################################################################################

        # print('calculando calculando ab_50pkts_2s')
        # 50 pacotes IAT 2s         ##################################################################
        #ab
        saida = gerar_blocos_processar(block_size_max=50, block_size_min=50, file_name= 'ab.pcap', tabela_db='ab_50pkts_2s', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
        #ba
        saida = gerar_blocos_processar(block_size_max=50, block_size_min=50, file_name= 'ba.pcap', tabela_db='ab_50pkts_2s', proto=proto, service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False, tcptrace=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
        ##############################################################################################

        # alem disso, criar as bases específicas para TCP
        if proto == 'TCP':
            # print('calculando twoways total e limitado')
             #two ways
            saida = gerar_blocos_processar(file_name= file_name, tabela_db='fluxo_total_two_ways', proto=proto, service_class = service_class, app_class= app_class, qos_class= '0')  #two_way= True, block_size =None, idle_timeout=None) # talvez utilizar esses depois
            saida = gerar_blocos_processar(block_size_max=10, block_size_min=10, file_name= file_name, tabela_db='twoways_10pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2)  #two_way= True, block_size =None, idle_timeout=None) # talvez utilizar esses depois
            saida = gerar_blocos_processar(block_size_max=30, block_size_min=30, file_name= file_name, tabela_db='twoways_30pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2)  #two_way= True, block_size =None, idle_timeout=None) # talvez utilizar esses depois
            saida = gerar_blocos_processar(block_size_max=50, block_size_min=50, file_name= file_name, tabela_db='twoways_50pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2)  #two_way= True, block_size =None, idle_timeout=None) # talvez utilizar esses depois

            # print('calculando ab_Tcp')
            #10 pkts
            #ab
            saida = gerar_blocos_processar(block_size_max=10, block_size_min=10, file_name= 'ab.pcap', tabela_db='ab_tcp_10pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
            #ba
            saida = gerar_blocos_processar(block_size_max=10, block_size_min=10, file_name= 'ba.pcap', tabela_db='ab_tcp_10pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u

            #30 pkts
            saida = gerar_blocos_processar(block_size_max=30, block_size_min=30, file_name= 'ab.pcap', tabela_db='ab_tcp_30pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
            #ba
            saida = gerar_blocos_processar(block_size_max=30, block_size_min=30, file_name= 'ba.pcap', tabela_db='ab_tcp_30pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u

            #50 pkts
            saida = gerar_blocos_processar(block_size_max=50, block_size_min=50, file_name= 'ab.pcap', tabela_db='ab_tcp_50pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
            #ba
            saida = gerar_blocos_processar(block_size_max=50, block_size_min=50, file_name= 'ba.pcap', tabela_db='ab_tcp_50pkts_2s', proto='TCP', service_class = service_class, app_class= app_class, qos_class= qos_class, idle_timeout=2, two_way=False)  #two_way= True, block_size =None, idle_timeout=None) # talvez u
      
        print("[fim]:", file_name)

        # remover os arquivos temporarios one way criados

    #     if os.path.exists('db_inserts.dat'):
    #         print('[db] inserindo na base ')
    #         file = open('db_inserts.dat','r')

    #         for linha in file:
    #             #submit to DB 
    #             if linha != '':
    #                 linha = linha.replace("'NA'", "'0'")
    #                 if dbconn.manipular(sql = linha) == False:
    #                     print('[DB-fail]: ', linha)
    #                     file = open('dberros.txt', 'a+')
    #                     file.write('[DB-fail]: ', linha)
    #                     file.close()
    #             # else:db_inserts.dat
    #             #     print("[db] Sucesso")

    # dbconn.fechar()
    try:
        os.remove('ab.pcap')
        os.remove('ba.pcap')
        os.remove('db_inserts.dat')
    except:
        print('[erro] ao deletar os arquivos provisorios')    
        

