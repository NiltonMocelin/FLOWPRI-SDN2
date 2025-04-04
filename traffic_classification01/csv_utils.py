import pandas as pd
import numpy as np
import os
# from graficos import seaborn_boxplot_desenhar, seaborn_histo_desenhar

apps_list=["aim","bittorrent","email","facebook","ftps_down","ftps_up","ftps_updown","gmail","handgout","hangouts","icq","netflix","scp_down","scp_up","sftp_down","sftp_up","sftp_updown","skype","skype_updown","spotify","vimeo","voipbuster","youtube"]
service_list = ['chat_real', 'be', 'video_estatico', 'audio_real', 'video_real', 'audio_estatico']


ab_columns = ["proto","service_class","app_class","qos_class","qtd_pkts_total","ab_mean_iat_198","ab_med_iat_197","ab_std_iat_201","ab_min_iat_195","ab_max_iat_200","ab_q1_iat_196","ab_q3_iat_199","ab_sum_iat","ab_below_mean_iat","ab_above_mean_iat","no_transitions_bulktrans_210","time_spent_in_bulk_211","duration_connection_duration_212","bulk_percent_of_time_spent_213","time_spent_idle_214","idle_percent_of_time_215","ab_bytes_per_sec","ab_mean_data_control_163","ab_med_data_control_162","ab_var_data_control_166","ab_min_data_control_160","ab_max_data_control_165","ab_q1_data_control_161","ab_q3_data_control_164","ab_mean_data_ip_163","ab_med_data_ip_162","ab_var_data_ip_166","ab_min_data_ip_160","ab_max_data_ip_165","ab_q1_data_ip_161","ab_q3_data_ip_164","ab_min_data_control_307","ab_q1_data_control_308","ab_med_data_control_309","ab_mean_data_control_310","ab_q3_data_control_311","ab_max_data_control_312","ab_var_data_control_313","ab_mean_data_pkt_156","ab_med_data_pkt_155","ab_var_data_pkt_159","ab_min_data_pkt_153","ab_max_data_pkt_158","ab_q1_data_pkt_154","ab_q3_data_pkt_157","ab_mean_header_ip_ref321","ab_med_header_ip_ref322","ab_std_header_ip_ref323","ab_min_header_ip_ref324","ab_max_header_ip_ref325","ab_q1_header_ip_ref326","ab_q3_header_ip_ref327","ab_pkts_abv_1024","ab_pays_bel_128","ab_pays_in_128_1024","ab_pkts_abv_mean","ab_pkts_bel_mean","ab_pkts_header_sum","ab_pkts_len_sum","ab_pkts_per_sec"]
ab_tcp_columns = ["proto","service_class","app_class","qos_class","qtd_pkts_total","ab_mean_iat_198","ab_med_iat_197","ab_std_iat_201","ab_min_iat_195","ab_max_iat_200","ab_q1_iat_196","ab_q3_iat_199","ab_sum_iat","ab_below_mean_iat","ab_above_mean_iat","no_transitions_bulktrans_210","time_spent_in_bulk_211","duration_connection_duration_212","bulk_percent_of_time_spent_213","time_spent_idle_214","idle_percent_of_time_215","ab_bytes_per_sec","ab_mean_data_control_163","ab_med_data_control_162","ab_var_data_control_166","ab_min_data_control_160","ab_max_data_control_165","ab_q1_data_control_161","ab_q3_data_control_164","ab_mean_data_ip_163","ab_med_data_ip_162","ab_var_data_ip_166","ab_min_data_ip_160","ab_max_data_ip_165","ab_q1_data_ip_161","ab_q3_data_ip_164","ab_min_data_control_307","ab_q1_data_control_308","ab_med_data_control_309","ab_mean_data_control_310","ab_q3_data_control_311","ab_max_data_control_312","ab_var_data_control_313","ab_mean_data_pkt_156","ab_med_data_pkt_155","ab_var_data_pkt_159","ab_min_data_pkt_153","ab_max_data_pkt_158","ab_q1_data_pkt_154","ab_q3_data_pkt_157","ab_mean_header_ip_ref321","ab_med_header_ip_ref322","ab_std_header_ip_ref323","ab_min_header_ip_ref324","ab_max_header_ip_ref325","ab_q1_header_ip_ref326","ab_q3_header_ip_ref327","ab_pkts_abv_1024","ab_pays_bel_128","ab_pays_in_128_1024","ab_pkts_abv_mean","ab_pkts_bel_mean","ab_pkts_header_sum","ab_pkts_len_sum","ab_pkts_per_sec","first_packet","last_packet","total_packets_a2b","resets_sent_a2b","ack_pkts_sent_a2b","pure_acks_sent_a2b","sack_pkts_sent_a2b","dsack_pkts_sent_a2b","max_sack_blkslack_a2b","unique_bytes_sent_a2b","actual_data_pkts_a2b","actual_data_bytes_a2b","rexmt_data_pkts_a2b","rexmt_data_bytes_a2b","zwnd_probe_pkts_a2b","zwnd_probe_bytes_a2b","outoforder_pkts_a2b","pushed_data_pkts_a2b","synlfin_pkts_sent_a2b","req_1323_wslts_a2b","adv_wind_scale_a2b","req_sack_a2b","sacks_sent_a2b","urgent_data_pkts_a2b","urgent_data_bytes_a2b","mss_requested_a2b","max_segm_size_a2b","min_segm_size_a2b","avg_segm_size_a2b","max_win_adv_a2b","min_win_adv_a2b","zero_win_adv_a2b","avg_win_adv_a2b","max_owin_a2b","min_nonzero_owin_a2b","avg_owin_a2b","wavg_owin_a2b","initial_window_bytes_a2b","initial_window_pkts_a2b","ttl_stream_length_a2b","missed_data_a2b","truncated_data_a2b","truncated_packets_a2b","data_xmit_time_a2b","idletime_max_a2b","hardware_dups_a2b","throughput_a2b","rtt_samples_a2b","rtt_min_a2b","rtt_max_a2b","rtt_avg_a2b","rtt_stdev_a2b","rtt_from_3whs_a2b","rtt_full_sz_smpls_a2b","rtt_full_sz_min_a2b","rtt_full_sz_max_a2b","rtt_full_sz_avg_a2b","rttfull_sz_stdev_a2b","postloss_acks_a2b","ambiguous_acks_a2b","rtt_min_last_a2b","rtt_max_last_a2b","rtt_avg_last_a2b","rtt_sdv_last_a2b","segs_cum_acked_a2b","duplicate_acks_a2b","triple_dupacks_a2b","max_retrans_a2b","min_retr_time_a2b","max_retr_time_a2b","avg_retr_time_a2b","sdv_retr_time_a2b"]
total_two_ways_columns = ["proto","service_class","app_class","qos_class","qtd_pkts_total","ab_mean_iat_198","ab_med_iat_197","ab_std_iat_201","ab_min_iat_195","ab_max_iat_200","ab_q1_iat_196","ab_q3_iat_199","ab_sum_iat","ab_below_mean_iat","ab_above_mean_iat","ba_mean_iat_205","ba_med_iat_204","ba_std_iat_208","ba_min_iat_202","ba_max_iat_207","ba_q1_iat_203","ba_q3_iat_206","ba_sum_iat","ba_below_mean_iat","ba_above_mean_iat","mean_iat_ref6","med_iat_ref5","min_iat_ref3","q1_iat_ref4","q3_iat_ref3","max_iat_ref8","std_iat_ref9","sum_iat","below_mean_iat","above_mean_iat","no_transitions_bulktrans_210","time_spent_in_bulk_211","duration_connection_duration_212","bulk_percent_of_time_spent_213","time_spent_idle_214","idle_percent_of_time_215","ab_bytes_per_sec","ab_mean_data_control_163","ab_med_data_control_162","ab_var_data_control_166","ab_min_data_control_160","ab_max_data_control_165","ab_q1_data_control_161","ab_q3_data_control_164","ab_mean_data_ip_163","ab_med_data_ip_162","ab_var_data_ip_166","ab_min_data_ip_160","ab_max_data_ip_165","ab_q1_data_ip_161","ab_q3_data_ip_164","ab_min_data_control_307","ab_q1_data_control_308","ab_med_data_control_309","ab_mean_data_control_310","ab_q3_data_control_311","ab_max_data_control_312","ab_var_data_control_313","ab_mean_data_pkt_156","ab_med_data_pkt_155","ab_var_data_pkt_159","ab_min_data_pkt_153","ab_max_data_pkt_158","ab_q1_data_pkt_154","ab_q3_data_pkt_157","ab_mean_header_ip_ref321","ab_med_header_ip_ref322","ab_std_header_ip_ref323","ab_min_header_ip_ref324","ab_max_header_ip_ref325","ab_q1_header_ip_ref326","ab_q3_header_ip_ref327","ab_pkts_abv_1024","ab_pays_bel_128","ab_pays_in_128_1024","ab_pkts_abv_mean","ab_pkts_bel_mean","ab_pkts_header_sum","ab_pkts_len_sum","ab_pkts_per_sec","ba_bytes_per_sec","ba_mean_data_control_184","ba_med_data_control_183","ba_var_data_control_187","ba_min_data_control_181","ba_max_data_control_186","ba_q1_data_control_182","ba_q3_data_control_185","ba_mean_data_ip_184","ba_med_data_ip_183","ba_var_data_ip_187","ba_min_data_ip_181","ba_max_data_ip_186","ba_q1_data_ip_182","ba_q3_data_ip_185","ba_min_data_control_314","ba_q1_data_control_315","ba_med_data_control_316","ba_mean_data_control_317","ba_q3_data_control_318","ba_max_data_control_319","ba_var_data_control_320","ba_mean_data_pkt_177","ba_med_data_pkt_176","ba_var_data_pkt_180","ba_min_data_pkt_174","ba_max_data_pkt_179","ba_q1_data_pkt_175","ba_q3_data_pkt_178","ba_mean_header_ip_ref191","ba_med_header_ip_ref190","ba_std_header_ip_ref194","ba_min_header_ip_ref188","ba_max_header_ip_ref193","ba_q1_header_ip_ref189","ba_q3_header_ip_ref192","ba_pays_abv_1024","ba_pays_bel_128","ba_pays_in_128_1024","ba_pkts_abv_mean","ba_pkts_bel_mean","ba_pkts_header_sum","ba_pkts_len_sum","ba_pkts_per_sec","bytes_per_sec","mean_data_control_ref27","med_data_control_ref26","std_data_control_ref30","min_data_control_ref24","max_data_control_ref29","q1_data_control_ref25","q3_data_control_ref28","mean_data_ip_ref20","med_data_ip_ref19","std_data_ip_ref23","min_data_ip_ref17","max_data_ip_ref22","q1_data_ip_ref18","q3_data_ip_ref21","mean_data_payload_ref300","med_data_payload_ref301","std_data_payload_ref302","min_data_payload_ref303","max_data_payload_ref304","q1_data_payload_ref305","q3_data_payload_ref306","mean_data_pkt_ref13","med_data_pkt_ref12","std_data_pkt_ref16","min_data_pkt_ref10","max_data_pkt_ref15","q1_data_pkt_ref11","q3_data_pkt_ref14","mean_header_ip_ref27","med_header_ip_ref26","std_header_ip_ref30","min_header_ip_ref24","max_header_ip_ref29","q1_header_ip_ref25","q3_header_ip_ref28","pays_abv_1024","pays_bel_128","pays_in_128_1024","pkts_abv_mean","pkts_bel_mean","pkts_header_sum","pkts_len_sum","pkts_per_sec","first_packet","last_packet","total_packets_a2b","total_packets_b2a","resets_sent_a2b","resets_sent_b2a","ack_pkts_sent_a2b","ack_pkts_sent_b2a","pure_acks_sent_a2b","pure_acks_sent_b2a","sack_pkts_sent_a2b","sack_pkts_sent_b2a","dsack_pkts_sent_a2b","dsack_pkts_sent_b2a","max_sack_blkslack_a2b","max_sack_blkslack_b2a","unique_bytes_sent_a2b","unique_bytes_sent_b2a","actual_data_pkts_a2b","actual_data_pkts_b2a","actual_data_bytes_a2b","actual_data_bytes_b2a","rexmt_data_pkts_a2b","rexmt_data_pkts_b2a","rexmt_data_bytes_a2b","rexmt_data_bytes_b2a","zwnd_probe_pkts_a2b","zwnd_probe_pkts_b2a","zwnd_probe_bytes_a2b","zwnd_probe_bytes_b2a","outoforder_pkts_a2b","outoforder_pkts_b2a","pushed_data_pkts_a2b","pushed_data_pkts_b2a","synlfin_pkts_sent_a2b","synlfin_pkts_sent_b2a","req_1323_wslts_a2b","req_1323_wslts_b2a","adv_wind_scale_a2b","adv_wind_scale_b2a","req_sack_a2b","req_sack_b2a","sacks_sent_a2b","sacks_sent_b2a","urgent_data_pkts_a2b","urgent_data_pkts_b2a","urgent_data_bytes_a2b","urgent_data_bytes_b2a","mss_requested_a2b","mss_requested_b2a","max_segm_size_a2b","max_segm_size_b2a","min_segm_size_a2b","min_segm_size_b2a","avg_segm_size_a2b","avg_segm_size_b2a","max_win_adv_a2b","max_win_adv_b2a","min_win_adv_a2b","min_win_adv_b2a","zero_win_adv_a2b","zero_win_adv_b2a","avg_win_adv_a2b","avg_win_adv_b2a","max_owin_a2b","max_owin_b2a","min_nonzero_owin_a2b","min_nonzero_owin_b2a","avg_owin_a2b","avg_owin_b2a","wavg_owin_a2b","wavg_owin_b2a","initial_window_bytes_a2b","initial_window_bytes_b2a","initial_window_pkts_a2b","initial_window_pkts_b2a","ttl_stream_length_a2b","ttl_stream_length_b2a","missed_data_a2b","missed_data_b2a","truncated_data_a2b","truncated_data_b2a","truncated_packets_a2b","truncated_packets_b2a","data_xmit_time_a2b","data_xmit_time_b2a","idletime_max_a2b","idletime_max_b2a","hardware_dups_a2b","hardware_dups_b2a","throughput_a2b","throughput_b2a","rtt_samples_a2b","rtt_samples_b2a","rtt_min_a2b","rtt_min_b2a","rtt_max_a2b","rtt_max_b2a","rtt_avg_a2b","rtt_avg_b2a","rtt_stdev_a2b","rtt_stdev_b2a","rtt_from_3whs_a2b","rtt_from_3whs_b2a","rtt_full_sz_smpls_a2b","rtt_full_sz_smpls_b2a","rtt_full_sz_min_a2b","rtt_full_sz_min_b2a","rtt_full_sz_max_a2b","rtt_full_sz_max_b2a","rtt_full_sz_avg_a2b","rtt_full_sz_avg_b2a","rttfull_sz_stdev_a2b","rtt_full_sz_stdev_b2a","postloss_acks_a2b","postloss_acks_b2a","ambiguous_acks_a2b","ambiguous_acks_b2a","rtt_min_last_a2b","rtt_min_last_b2a","rtt_max_last_a2b","rtt_max_last_b2a","rtt_avg_last_a2b","rtt_avg_last_b2a","rtt_sdv_last_a2b","rtt_sdv_last_b2a","segs_cum_acked_a2b","segs_cum_acked_b2a","duplicate_acks_a2b","duplicate_acks_b2a","triple_dupacks_a2b","triple_dupacks_b2a","max_retrans_a2b","max_retrans_b2a","min_retr_time_a2b","min_retr_time_b2a","max_retr_time_a2b","max_retr_time_b2a","avg_retr_time_a2b","avg_retr_time_b2a","sdv_retr_time_a2b","sdv_retr_time_b2a"]
twoways_columns = ["proto","service_class","app_class","qos_class","qtd_pkts_total","ab_mean_iat_198","ab_med_iat_197","ab_std_iat_201","ab_min_iat_195","ab_max_iat_200","ab_q1_iat_196","ab_q3_iat_199","ab_sum_iat","ab_below_mean_iat","ab_above_mean_iat","ba_mean_iat_205","ba_med_iat_204","ba_std_iat_208","ba_min_iat_202","ba_max_iat_207","ba_q1_iat_203","ba_q3_iat_206","ba_sum_iat","ba_below_mean_iat","ba_above_mean_iat","mean_iat_ref6","med_iat_ref5","min_iat_ref3","q1_iat_ref4","q3_iat_ref3","max_iat_ref8","std_iat_ref9","sum_iat","below_mean_iat","above_mean_iat","no_transitions_bulktrans_210","time_spent_in_bulk_211","duration_connection_duration_212","bulk_percent_of_time_spent_213","time_spent_idle_214","idle_percent_of_time_215","ab_bytes_per_sec","ab_mean_data_control_163","ab_med_data_control_162","ab_var_data_control_166","ab_min_data_control_160","ab_max_data_control_165","ab_q1_data_control_161","ab_q3_data_control_164","ab_mean_data_ip_163","ab_med_data_ip_162","ab_var_data_ip_166","ab_min_data_ip_160","ab_max_data_ip_165","ab_q1_data_ip_161","ab_q3_data_ip_164","ab_min_data_control_307","ab_q1_data_control_308","ab_med_data_control_309","ab_mean_data_control_310","ab_q3_data_control_311","ab_max_data_control_312","ab_var_data_control_313","ab_mean_data_pkt_156","ab_med_data_pkt_155","ab_var_data_pkt_159","ab_min_data_pkt_153","ab_max_data_pkt_158","ab_q1_data_pkt_154","ab_q3_data_pkt_157","ab_mean_header_ip_ref321","ab_med_header_ip_ref322","ab_std_header_ip_ref323","ab_min_header_ip_ref324","ab_max_header_ip_ref325","ab_q1_header_ip_ref326","ab_q3_header_ip_ref327","ab_pkts_abv_1024","ab_pays_bel_128","ab_pays_in_128_1024","ab_pkts_abv_mean","ab_pkts_bel_mean","ab_pkts_header_sum","ab_pkts_len_sum","ab_pkts_per_sec","ba_bytes_per_sec","ba_mean_data_control_184","ba_med_data_control_183","ba_var_data_control_187","ba_min_data_control_181","ba_max_data_control_186","ba_q1_data_control_182","ba_q3_data_control_185","ba_mean_data_ip_184","ba_med_data_ip_183","ba_var_data_ip_187","ba_min_data_ip_181","ba_max_data_ip_186","ba_q1_data_ip_182","ba_q3_data_ip_185","ba_min_data_control_314","ba_q1_data_control_315","ba_med_data_control_316","ba_mean_data_control_317","ba_q3_data_control_318","ba_max_data_control_319","ba_var_data_control_320","ba_mean_data_pkt_177","ba_med_data_pkt_176","ba_var_data_pkt_180","ba_min_data_pkt_174","ba_max_data_pkt_179","ba_q1_data_pkt_175","ba_q3_data_pkt_178","ba_mean_header_ip_ref191","ba_med_header_ip_ref190","ba_std_header_ip_ref194","ba_min_header_ip_ref188","ba_max_header_ip_ref193","ba_q1_header_ip_ref189","ba_q3_header_ip_ref192","ba_pays_abv_1024","ba_pays_bel_128","ba_pays_in_128_1024","ba_pkts_abv_mean","ba_pkts_bel_mean","ba_pkts_header_sum","ba_pkts_len_sum","ba_pkts_per_sec","bytes_per_sec","mean_data_control_ref27","med_data_control_ref26","std_data_control_ref30","min_data_control_ref24","max_data_control_ref29","q1_data_control_ref25","q3_data_control_ref28","mean_data_ip_ref20","med_data_ip_ref19","std_data_ip_ref23","min_data_ip_ref17","max_data_ip_ref22","q1_data_ip_ref18","q3_data_ip_ref21","mean_data_payload_ref300","med_data_payload_ref301","std_data_payload_ref302","min_data_payload_ref303","max_data_payload_ref304","q1_data_payload_ref305","q3_data_payload_ref306","mean_data_pkt_ref13","med_data_pkt_ref12","std_data_pkt_ref16","min_data_pkt_ref10","max_data_pkt_ref15","q1_data_pkt_ref11","q3_data_pkt_ref14","mean_header_ip_ref27","med_header_ip_ref26","std_header_ip_ref30","min_header_ip_ref24","max_header_ip_ref29","q1_header_ip_ref25","q3_header_ip_ref28","pays_abv_1024","pays_bel_128","pays_in_128_1024","pkts_abv_mean","pkts_bel_mean","pkts_header_sum","pkts_len_sum","pkts_per_sec","first_packet","last_packet","total_packets_a2b","total_packets_b2a","resets_sent_a2b","resets_sent_b2a","ack_pkts_sent_a2b","ack_pkts_sent_b2a","pure_acks_sent_a2b","pure_acks_sent_b2a","sack_pkts_sent_a2b","sack_pkts_sent_b2a","dsack_pkts_sent_a2b","dsack_pkts_sent_b2a","max_sack_blkslack_a2b","max_sack_blkslack_b2a","unique_bytes_sent_a2b","unique_bytes_sent_b2a","actual_data_pkts_a2b","actual_data_pkts_b2a","actual_data_bytes_a2b","actual_data_bytes_b2a","rexmt_data_pkts_a2b","rexmt_data_pkts_b2a","rexmt_data_bytes_a2b","rexmt_data_bytes_b2a","zwnd_probe_pkts_a2b","zwnd_probe_pkts_b2a","zwnd_probe_bytes_a2b","zwnd_probe_bytes_b2a","outoforder_pkts_a2b","outoforder_pkts_b2a","pushed_data_pkts_a2b","pushed_data_pkts_b2a","synlfin_pkts_sent_a2b","synlfin_pkts_sent_b2a","req_1323_wslts_a2b","req_1323_wslts_b2a","adv_wind_scale_a2b","adv_wind_scale_b2a","req_sack_a2b","req_sack_b2a","sacks_sent_a2b","sacks_sent_b2a","urgent_data_pkts_a2b","urgent_data_pkts_b2a","urgent_data_bytes_a2b","urgent_data_bytes_b2a","mss_requested_a2b","mss_requested_b2a","max_segm_size_a2b","max_segm_size_b2a","min_segm_size_a2b","min_segm_size_b2a","avg_segm_size_a2b","avg_segm_size_b2a","max_win_adv_a2b","max_win_adv_b2a","min_win_adv_a2b","min_win_adv_b2a","zero_win_adv_a2b","zero_win_adv_b2a","avg_win_adv_a2b","avg_win_adv_b2a","max_owin_a2b","max_owin_b2a","min_nonzero_owin_a2b","min_nonzero_owin_b2a","avg_owin_a2b","avg_owin_b2a","wavg_owin_a2b","wavg_owin_b2a","initial_window_bytes_a2b","initial_window_bytes_b2a","initial_window_pkts_a2b","initial_window_pkts_b2a","ttl_stream_length_a2b","ttl_stream_length_b2a","missed_data_a2b","missed_data_b2a","truncated_data_a2b","truncated_data_b2a","truncated_packets_a2b","truncated_packets_b2a","data_xmit_time_a2b","data_xmit_time_b2a","idletime_max_a2b","idletime_max_b2a","hardware_dups_a2b","hardware_dups_b2a","throughput_a2b","throughput_b2a","rtt_samples_a2b","rtt_samples_b2a","rtt_min_a2b","rtt_min_b2a","rtt_max_a2b","rtt_max_b2a","rtt_avg_a2b","rtt_avg_b2a","rtt_stdev_a2b","rtt_stdev_b2a","rtt_from_3whs_a2b","rtt_from_3whs_b2a","rtt_full_sz_smpls_a2b","rtt_full_sz_smpls_b2a","rtt_full_sz_min_a2b","rtt_full_sz_min_b2a","rtt_full_sz_max_a2b","rtt_full_sz_max_b2a","rtt_full_sz_avg_a2b","rtt_full_sz_avg_b2a","rttfull_sz_stdev_a2b","rtt_full_sz_stdev_b2a","postloss_acks_a2b","postloss_acks_b2a","ambiguous_acks_a2b","ambiguous_acks_b2a","rtt_min_last_a2b","rtt_min_last_b2a","rtt_max_last_a2b","rtt_max_last_b2a","rtt_avg_last_a2b","rtt_avg_last_b2a","rtt_sdv_last_a2b","rtt_sdv_last_b2a","segs_cum_acked_a2b","segs_cum_acked_b2a","duplicate_acks_a2b","duplicate_acks_b2a","triple_dupacks_a2b","triple_dupacks_b2a","max_retrans_a2b","max_retrans_b2a","min_retr_time_a2b","min_retr_time_b2a","max_retr_time_a2b","max_retr_time_b2a","avg_retr_time_a2b","avg_retr_time_b2a","sdv_retr_time_a2b","sdv_retr_time_b2a"]
total_ab_columns = ["proto","service_class","app_class","qos_class","qtd_pkts_total","ab_mean_iat_198","ab_med_iat_197","ab_std_iat_201","ab_min_iat_195","ab_max_iat_200","ab_q1_iat_196","ab_q3_iat_199","ab_sum_iat","ab_below_mean_iat","ab_above_mean_iat","no_transitions_bulktrans_210","time_spent_in_bulk_211","duration_connection_duration_212","bulk_percent_of_time_spent_213","time_spent_idle_214","idle_percent_of_time_215","ab_bytes_per_sec","ab_mean_data_control_163","ab_med_data_control_162","ab_var_data_control_166","ab_min_data_control_160","ab_max_data_control_165","ab_q1_data_control_161","ab_q3_data_control_164","ab_mean_data_ip_163","ab_med_data_ip_162","ab_var_data_ip_166","ab_min_data_ip_160","ab_max_data_ip_165","ab_q1_data_ip_161","ab_q3_data_ip_164","ab_min_data_control_307","ab_q1_data_control_308","ab_med_data_control_309","ab_mean_data_control_310","ab_q3_data_control_311","ab_max_data_control_312","ab_var_data_control_313","ab_mean_data_pkt_156","ab_med_data_pkt_155","ab_var_data_pkt_159","ab_min_data_pkt_153","ab_max_data_pkt_158","ab_q1_data_pkt_154","ab_q3_data_pkt_157","ab_mean_header_ip_ref321","ab_med_header_ip_ref322","ab_std_header_ip_ref323","ab_min_header_ip_ref324","ab_max_header_ip_ref325","ab_q1_header_ip_ref326","ab_q3_header_ip_ref327","ab_pkts_abv_1024","ab_pays_bel_128","ab_pays_in_128_1024","ab_pkts_abv_mean","ab_pkts_bel_mean","ab_pkts_header_sum","ab_pkts_len_sum","ab_pkts_per_sec"]


fluxo_total_two_ways_max = [600.0421,120.21466,848.3239,0,2254.3337,45.22394,1799.7511,5871.9966,91489,19832,635.7885,890.0812,848.30695,0,2254.333,539.53296,1799.7303,5871.8193,42576,13555,300.02277,0.90006053,0,0.2990519,539.2646,2254.333,670.6907,5871.9966,99789,29157,99998,5855.5654,5871.9966,1,5871.9966,1.0003613,3.0353124,17585.053,17080,10584.706,1340,65192,11368,23280,17605.053,17100,10584.706,1360,65212,11388,23300,17553.047,17048,10584.716,1308,65160,11336,23248,17619.053,17114,10584.706,1360,65226,11402,23314,20,20,0,20,20,20,20,86249,94481,7691,86239,94158,2.765096e+06,1.9816126e+08,30896.25,5.7176504,32633.912,33336,19080.676,1326,65192,32788,33336,32653.912,33356,19080.676,1346,65212,32808,33356,32613.912,33304,19080.68,1306,65160,32768,33304,32667.912,33370,19080.676,1360,65226,32822,33370,20,20,0,20,20,20,20,45000,45514,5613,0,42988,1.49652e+06,1.024998e+09,39695.094,5.7176504,11356.8,3232,18282.568,48,65192,1440,17816,11356.8,3232,18282.568,48,65192,1440,17816,11324.797,3200,18282.57,28,65160,1420,17784,11390.8,3266,18282.568,82,65226,1474,17850,20,20,0,20,20,20,20,86249,94508,7717,86247,94534,3.26538e+06,11390.8,39695.094,1.6997658e+09,1.6997659e+09,94482,86626,71,10,94481,86626,94478,86624,11810,8629,197,51,4,4,1.021934e+09,4.0392874e+08,82135,86406,1.021934e+09,4.0392874e+08,583,197,714028,264687,0,0,0,0,1007,1367,18966,13325,1,1,1,1,0,0,1,1,11810,8629,0,0,0,0,1460,1460,65160,65160,2277,2676,29661,20802,4.194304e+06,2.114048e+06,4.194048e+06,1.048576e+06,155,153,4.194303e+06,1.67534e+06,1.8446744e+19,1.8446744e+19,1308,32769,8.0063994e+15,550040,3.4376363e+15,4.3392259e+15,33304,14850,15,11,4.0361494e+08,4.0392874e+08,1.8446744e+19,1.8446744e+19,0,0,0,0,5871.82,5871.819,5.402571e+06,5.4025275e+06,1,1,8.481963e+07,6.0188736e+07,43365,41780,552.9,511,1276,684.3,636,510.9,620.3,146.6,1276,511,33468,33314,1276,511,1276,511,1275.9,510.9,95.1,95.5,206,267,341,11,882,561.2,2016.9,561.2,971.9,561.2,916.2,62,72411,76732,7676,10607,89,142,8,5,13643.4,1529.8,31074.9,6679.8,13642.1,3572.3,10696.6,2387.8]
fluxo_total_ab_max = [1529.2129,1262.209,1620.0565,0,5093.319,984.8074,3436.8035,5886.0103,99792,79166,100000,5886.0103,5886.0103,1,5886.0103,1.0049875,10.585185,32455.242,33336,19080.676,1358,65192,32788,33336,32475.242,33356,19080.676,1378,65212,32808,33356,32435.242,33304,19080.68,1350,65160,32768,33304,32489.242,33370,19080.676,1392,65226,32822,33370,20,20,0,20,20,20,20,99979,100000,48413,99971,100000,3.245148e+06,1.0824296e+09,222222.22]
twoways_10pkts_2s_max = [1.2431291,1.031274,1.0148237,0,2.488591,1.031274,2.0777621,6.215646,9,9,1.4063133,1.760974,1.0600029,0,2.719496,1.760974,2.719496,6.949098,4,4,0.6949098,0.5210435,0,0.49548703,1.652528,1.9999979,0.8091564,6.949098,9,9,10,5.768095,6.949098,1.0563381,6.949098,1.1506224,307.8889,54476.8,65192,32288,32904,65192,65192,65192,54496.8,65212,32288,32924,65212,65212,65212,54444.8,65160,32288,32872,65160,65160,65160,54510.8,65226,32288,32938,65226,65226,65226,20,20,0,20,20,20,20,10,10,10,9,10,600,314356,7e+06,470.66666,65192,65192,32580,65192,65192,65192,65192,65212,65212,32580,65212,65212,65212,65212,65160,65160,32580,65160,65160,65160,65160,65226,65226,32580,65226,65226,65226,65226,20,20,0,20,20,20,20,5,5,5,0,5,300,263306,1e+07,470.66666,31448.8,34656,31921.75,16433,65192,16433,65192,31448.8,34656,31921.75,16433,65192,16433,65192,31416.8,34624,31921.75,16413,65160,16413,65160,31482.8,34690,31921.75,16467,65226,16467,65226,20,20,0,20,20,20,20,10,10,10,9,10,600,31482.8,1e+07,1.6997659e+09,1.6997659e+09,10,9,9,6,10,9,10,9,10,9,9,9,4,4,313960,272224,10,9,313960,272224,4,3,2515,2676,4,1,13380,625,9,8,10,9,1,1,1,1,0,0,1,1,10,9,0,0,0,0,1460,1460,65160,65160,65160,65160,65143,65143,4.194304e+06,1.048576e+06,4.194176e+06,1.048576e+06,2,4,4.194218e+06,1.048576e+06,1.8446744e+19,1.8446744e+19,254369,1.8446744e+19,9.223372e+18,1.8446744e+19,1.8189035e+19,1.7545212e+19,212500,12042,10,5,1797,17544,1,14844,0,0,0,0,6.215,6.216,3195.9,2488.6,1,0,2.2821053e+09,6.5400003e+09,5,4,1056.5,525.8,1056.5,690.6,1056.4,601.5,285.9,229.8,689.5,499.4,5,4,1056.5,677.3,1056.5,690.6,1056.4,677.2,161.7,151.3,2,2,1,1,561.2,882,561.2,882,561.2,881.9,0,0,9,8,6,4,1,1,4,2,2012.5,2309.2,2012.5,2309.2,2012.3,2309,381,242.2]
twoways_30pkts_2s_max = [1.0811313,1.0614849,0.85738486,0,2.488591,1.0010521,2.010018,17.298101,29,28,1.2343756,1.140326,0.9251094,0,2.719496,1.0012019,2.004588,17.28126,14,14,0.5903605,0.48442554,0,0.284454,0.96153593,1.9999839,0.7046099,17.710815,29,28,30,13.64162,17.710815,1.0185186,17.710815,1.0127101,56.235294,42760.535,40576,28186.35,32788,65192,32788,65192,42780.535,40596,28186.35,32808,65212,32808,65212,42728.535,40544,28186.35,32768,65160,32768,65160,42794.535,40610,28186.35,32822,65226,32822,65226,20,20,0,20,20,20,20,30,30,26,29,30,1800,656440,647058.8,45.538094,65192,65192,30439.297,65192,65192,65192,65192,65212,65212,30439.297,65212,65212,65212,65212,65160,65160,30439.297,65160,65160,65160,65160,65226,65226,30439.297,65226,65226,65226,65226,20,20,0,20,20,20,20,15,15,14,0,15,900,667000,638297.9,56.113476,22254.533,32788,29857.799,2708,65192,7272,65192,22254.533,32788,29857.799,2708,65192,7272,65192,22222.533,32768,29857.799,2676,65160,7240,65160,22288.533,32822,29857.799,2742,65226,7306,65226,20,20,0,20,20,20,20,30,30,26,29,30,1800,22288.533,638297.9,1.6997659e+09,1.6997659e+09,30,29,11,15,30,29,30,29,30,27,19,19,4,4,666208,640928,30,29,666208,640928,7,5,10704,21408,14,0,38802,0,18,17,30,28,1,1,1,1,0,0,1,1,30,27,0,0,0,0,1460,1460,65160,65160,33304,65160,58074,65152,4.194304e+06,1.048576e+06,4.194048e+06,1.048576e+06,2,6,4.194275e+06,1.048576e+06,1.8446744e+19,1.8446744e+19,254369,1.8446744e+19,1.6769768e+18,4.611686e+18,1.8265211e+19,1.7358033e+19,300329,14850,30,11,21713,58908,1,1,0,0,0,0,17.298,12.24,2719.5,3195.9,0,0,8.0851066e+08,4.0672726e+08,15,14,479.2,481,728.3,693.7,483.6,483.9,205.4,195.4,425,178.3,15,14,554.6,639.4,610.7,690.6,554.5,639.3,174.1,209.9,6,4,2,2,561.2,481.8,561.2,481.8,561.2,481.7,0,0,28,27,14,13,2,2,3,1,2012.5,1330.9,2012.5,2309.2,2012.3,1632.3,263.6,132]
twoways_50pkts_2s_max = [0.84607196,1.0131145,0.84636456,0,2.488591,0.5295921,1.627151,23.690016,49,40,1.0035444,1.0188131,0.91639996,0,2.719496,1.000047,2.00501,22.269001,24,24,0.4773672,0.4829046,0,0.28001606,0.81308603,1.9999839,0.70550084,23.868359,49,44,50,21.699894,23.868359,1.0029585,23.868359,1.0128299,53.26829,32904,32904,24944.824,20304,65192,24608,65192,32924,32924,24944.824,20324,65212,24628,65212,32872,32872,24944.824,20272,65160,24576,65160,32938,32938,24944.824,20338,65226,24642,65226,20,20,0,20,20,20,20,50,50,36,49,50,3000,856388,609756.1,45.061054,54043,65192,29848.01,33336,65192,65192,65192,54063,65212,29848.01,33356,65212,65212,65212,54011,65160,29848.01,33304,65160,65160,65160,54077,65226,29848.01,33370,65226,65226,65226,20,20,0,20,20,20,20,25,25,21,0,25,1500,865232,609756.1,53.26829,17323.84,16468,28460.658,1480,65192,5824,65192,17323.84,16468,28460.658,1480,65192,5824,65192,17291.84,16436,28460.658,1460,65160,5792,65160,17357.84,16502,28460.658,1514,65226,5858,65226,20,20,0,20,20,20,20,50,50,36,49,50,3000,17357.84,609756.1,1.6997659e+09,1.6997659e+09,50,49,0,25,50,49,50,49,50,49,29,28,4,4,864176,839432,50,49,864176,839432,4,11,9366,30774,24,0,66900,0,24,37,50,48,1,1,1,1,0,0,1,1,50,49,0,0,0,0,1460,1460,65160,65160,33304,42444,57607,57631,4.194304e+06,1.048576e+06,4.194048e+06,1.048576e+06,4,6,4.194282e+06,1.048576e+06,1.8446744e+19,1.8446744e+19,204277,1.8446744e+19,1.0248191e+18,2.305843e+18,1.8369343e+19,1.6354653e+19,421643,14850,50,11,1433,40918,0,0,0,0,0,0,22.083,22.079,2719.5,3195.9,0,0,7.6731706e+08,4.9103126e+08,25,24,329.8,353.3,693.7,728.3,470.7,453.1,179.4,163.4,403.1,1.8,25,24,545.7,490.3,574.4,606,545.6,490.2,140.7,119.3,7,9,2,2,561.2,418.2,561.2,418.2,561.2,418.1,0,0,48,47,24,23,3,3,3,6,2012.5,1394.8,2012.5,3059.7,2012.3,1565,215,1301.7]

ab_tcp_10pkts_max = [0.9503793,1.0286765,0.8820836,0,1.999507,1.0100559,1.823764,9.503793,9,9,10,9.503793,9.503793,1,9.503793,1.146862,133.71428,65192,65192,30460.438,65192,65192,65192,65192,65212,65212,30460.438,65212,65212,65212,65212,65160,65160,30460.438,65160,65160,65160,65160,65226,65226,30460.438,65226,65226,65226,65226,20,20,0,20,20,20,20,10,10,10,9,10,600,652260,3.3333332e+06,1.6997659e+09,1.6997659e+09,10,10,10,10,10,10,4,651600,10,651600,5,9366,0,0,9,10,1,1,0,1,10,0,0,1460,65160,65160,65153,65535,65535,5,65535,88380,65160,65160,64447,651600,10,17544,1.8446744e+19,0,0,9.213,2331.2,1,1.9285714e+09,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,3059.7,3059.7,3059.4,675.7]
ab_tcp_30pkts_max = [0.8464766,1.00955,0.8172365,0,1.99936,0.7828629,1.7741079,25.394299,29,29,30,24.275267,25.394299,1,25.394299,1.0145053,51.712418,43493.066,45682,26964.79,33336,65192,33336,65192,43513.066,45702,26964.79,33356,65212,33356,65212,43461.066,45650,26964.79,33304,65160,33304,65160,43527.066,45716,26964.79,33370,65226,33370,65226,20,20,0,20,20,20,20,30,30,30,29,30,1800,1.305812e+06,600000,1.6997659e+09,1.6997659e+09,30,30,30,30,30,30,4,1.303832e+06,30,1.303832e+06,11,22746,0,0,29,30,1,1,0,1,30,0,0,1460,65160,33304,47096,65535,65535,7,65535,479587,33304,200075,143881,1.303832e+06,30,35863,1,0,0,24.36,2331.2,0,7.4509805e+08,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,1844.1,3059.7,1843.9,1388.2]
ab_tcp_50pkts_max = [0.8741246,1.010107,0.8237151,0,1.9991701,1.000044,1.752049,43.70623,49,48,50,42.020344,43.70623,1,43.70623,1.0070341,49.636364,41122,41946,25218.508,33336,65192,33336,65192,41142,41966,25218.508,33356,65212,33356,65212,41090,41914,25218.508,33304,65160,33304,65160,41156,41980,25218.508,33370,65226,33370,65226,20,20,0,20,20,20,20,50,50,50,49,50,3000,2.0578e+06,568181.8,1.6997659e+09,1.6997659e+09,50,50,50,50,50,50,4,2.0545e+06,50,2.0545e+06,14,50844,0,0,49,50,1,1,0,1,50,0,0,1460,65160,33304,43012,65535,65535,10,65535,1.004692e+06,33304,431211,355538,2.0545e+06,50,86087,27000,0,0,42.185,2331.2,0,7.15e+08,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,1427.1,3059.7,2007.5,651.9]

ab_10pkts_max = [1.5843456,1.920156,0.8820836,0,1.9999889,1.4402361,1.920487,15.843456,9,9,10,15.843456,15.843456,1,15.843456,1.146862,133.71428,65192,65192,30460.438,65192,65192,65192,65192,65212,65212,30460.438,65212,65212,65212,65212,65160,65160,30460.438,65160,65160,65160,65160,65226,65226,30460.438,65226,65226,65226,65226,20,20,0,20,20,20,20,10,10,10,9,10,600,652260,3.3333332e+06]
ab_30pkts_max = [1.1682932, 1.600143, 0.8172365, 0, 1.9999889, 0.96148396, 1.7741079, 35.048798, 29, 29, 30, 35.048798, 35.048798, 1, 35.048798, 1.0145053, 51.712418, 43493.066, 45682, 26964.79, 33336, 65192, 33336, 65192, 43513.066, 45702, 26964.79, 33356, 65212, 33356, 65212, 43461.066, 45650, 26964.79, 33304, 65160, 33304, 65160, 43527.066, 45716, 26964.79, 33370, 65226, 33370, 65226, 20, 20, 0, 20, 20, 20, 20, 30, 30, 30, 29, 30, 1800, 1.305812e+06, 600000]
ab_50pkts_max = [1.0851228, 1.600003, 0.8237151, 0, 1.9991701, 1.000044, 1.752049, 54.25614, 49, 49, 50, 54.25614, 54.25614, 1, 54.25614, 1.0070341, 49.636364, 41122, 41946, 25218.508, 33336, 65192, 33336, 65192, 41142, 41966, 25218.508, 33356, 65212, 33356, 65212, 41090, 41914, 25218.508, 33304, 65160, 33304, 65160, 41156, 41980, 25218.508, 33370, 65226, 33370, 65226, 20, 20, 0, 20, 20, 20, 20, 50, 50, 50, 49, 50, 3000, 2.0578e+06, 568181.8]


maiores_valores_list_div_global_normalizar = []
index_maiores_valores_list_div_global_normalizar = 0

def div_global_normalizar(x):
    """Funcao não segura !!!! NAO PARALELIZAR CUIDADO"""

    global index_maiores_valores_list_div_global_normalizar
    global maiores_valores_list_div_global_normalizar

    valor = maiores_valores_list_div_global_normalizar[index_maiores_valores_list_div_global_normalizar]

    if valor == 0:
        return 0

    return x/valor if type(valor) != str else 0

def csv_to_dataframe(nome_arquivo):
    return pd.read_csv(nome_arquivo)


def csv_maiores_valores(nome_arquivo_csv):

    lista_nom_final = []
    chunksize = 10 ** 5
    for chunk in pd.read_csv(nome_arquivo_csv, chunksize=chunksize, sep=','):
        # gerar_graficos(chunk)
        # remover_duplicados(chunk)
        lista_nom = chunk.max().to_list()

        for i in range(0, len(lista_nom_final)):
            if lista_nom_final[i] < lista_nom[i]:
                lista_nom_final[i] = lista_nom[i]

    return lista_nom_final 

def normalizar_dataframe(dataframe, maiores_valores):

    global index_maiores_valores_list_div_global_normalizar
    global maiores_valores_list_div_global_normalizar

    maiores_valores_list_div_global_normalizar = maiores_valores
    nomes_colunas = list(dataframe.columns)
    
    index_maiores_valores_list_div_global_normalizar=0

    # print(dataframe[nomes_colunas[0]])
    for nome in nomes_colunas:
        dataframe[nome] = dataframe[nome].apply(div_global_normalizar)
        index_maiores_valores_list_div_global_normalizar+=1

    return dataframe

def csv_normalizar(filename):
    chunksize = 10 ** 6

    # obter os maiores valores da base para cada coluna
    lista_nom = csv_maiores_valores(filename)

    for chunk in pd.read_csv(filename, chunksize=chunksize, sep=','):
        # gerar_graficos(chunk)
        # remover_duplicados(chunk)
        
        #normalizar conforme o maior valor da base --> entre 0 e 1
        normalizar_dataframe(chunk, lista_nom)

        # salvar chunk em arquivo

def remover_duplicados(dataframe):
    # newdf = dataframe.drop_duplicates(subset = ['proto','service_class','app_class','qos_class','qtd_pkts_total','ab_mean_iat_198','ab_med_iat_197','ab_std_iat_201','ab_min_iat_195','ab_max_iat_200','ab_q1_iat_196','ab_q3_iat_199','ab_sum_iat','ab_below_mean_iat','ab_above_mean_iat','no_transitions_bulktrans_210','time_spent_in_bulk_211','duration_connection_duration_212','bulk_percent_of_time_spent_213','time_spent_idle_214','idle_percent_of_time_215','ab_bytes_per_sec','ab_mean_data_control_163','ab_med_data_control_162','ab_var_data_control_166','ab_min_data_control_160','ab_max_data_control_165','ab_q1_data_control_161','ab_q3_data_control_164','ab_mean_data_ip_163','ab_med_data_ip_162','ab_var_data_ip_166','ab_min_data_ip_160','ab_max_data_ip_165','ab_q1_data_ip_161','ab_q3_data_ip_164','ab_min_data_control_307','ab_q1_data_control_308','ab_med_data_control_309','ab_mean_data_control_310','ab_q3_data_control_311','ab_max_data_control_312','ab_var_data_control_313','ab_mean_data_pkt_156','ab_med_data_pkt_155','ab_var_data_pkt_159','ab_min_data_pkt_153','ab_max_data_pkt_158','ab_q1_data_pkt_154','ab_q3_data_pkt_157','ab_mean_header_ip_ref321','ab_med_header_ip_ref322','ab_std_header_ip_ref323','ab_min_header_ip_ref324','ab_max_header_ip_ref325','ab_q1_header_ip_ref326','ab_q3_header_ip_ref327','ab_pkts_abv_1024','ab_pays_bel_128','ab_pays_in_128_1024','ab_pkts_abv_mean','ab_pkts_bel_mean','ab_pkts_header_sum','ab_pkts_len_sum', 'ab_pkts_per_sec'],
    #                                   keep = 'last').reset_index(drop = True) 
    nomes_colunas = list(dataframe.columns)

    # nomes_colunas.remove("service_class")
    # nomes_colunas.remove("app_class")
    # nomes_colunas.remove("proto")

    newdf = dataframe.drop_duplicates(subset = nomes_colunas,
                                      keep = 'last').reset_index(drop = True) 
    print('original: ', len(dataframe), ' x semdup: ', len(newdf))

    # tentar encontrar apenas os repetidos ?
    # newdf = dataframe.groupby(['proto','service_class','app_class','qos_class','qtd_pkts_total','ab_mean_iat_198','ab_med_iat_197','ab_std_iat_201','ab_min_iat_195','ab_max_iat_200','ab_q1_iat_196','ab_q3_iat_199','ab_sum_iat','ab_below_mean_iat','ab_above_mean_iat','no_transitions_bulktrans_210','time_spent_in_bulk_211','duration_connection_duration_212','bulk_percent_of_time_spent_213','time_spent_idle_214','idle_percent_of_time_215','ab_bytes_per_sec','ab_mean_data_control_163','ab_med_data_control_162','ab_var_data_control_166','ab_min_data_control_160','ab_max_data_control_165','ab_q1_data_control_161','ab_q3_data_control_164','ab_mean_data_ip_163','ab_med_data_ip_162','ab_var_data_ip_166','ab_min_data_ip_160','ab_max_data_ip_165','ab_q1_data_ip_161','ab_q3_data_ip_164','ab_min_data_control_307','ab_q1_data_control_308','ab_med_data_control_309','ab_mean_data_control_310','ab_q3_data_control_311','ab_max_data_control_312','ab_var_data_control_313','ab_mean_data_pkt_156','ab_med_data_pkt_155','ab_var_data_pkt_159','ab_min_data_pkt_153','ab_max_data_pkt_158','ab_q1_data_pkt_154','ab_q3_data_pkt_157','ab_mean_header_ip_ref321','ab_med_header_ip_ref322','ab_std_header_ip_ref323','ab_min_header_ip_ref324','ab_max_header_ip_ref325','ab_q1_header_ip_ref326','ab_q3_header_ip_ref327','ab_pkts_abv_1024','ab_pays_bel_128','ab_pays_in_128_1024','ab_pkts_abv_mean','ab_pkts_bel_mean','ab_pkts_header_sum','ab_pkts_len_sum', 'ab_pkts_per_sec']).apply(lambda x: x)
    # print(newdf['id'])
    # exit(0)
    return newdf

def remover_duplicados_csvfile_to_new_csvfile(input_filename, output_filename):
    chunksize = 10 ** 6
    chunkss = 0
    for chunk in pd.read_csv(input_filename, chunksize=chunksize, sep=','):
        chunk = remover_duplicados(chunk)

        dataframe_to_csvfile(chunk, output_filename,True if chunkss == 0 else False, True)
        chunkss+=1    

def dataframe_col_to_list(df):
    lista = []

    return lista

def dataframe_to_csvfile(df, filename, header=True, append=True):
    df.to_csv(filename, mode='a' if append else 'w', index=False, header=header)

def add_id_to_csv():
    _file_list = os.listdir('.')

    for file_name in _file_list:
        if '.csv' not in file_name: #.endswith('.csv'):
            continue
        _input_file = open(file_name, "r+")
        _output_file = open("new"+ file_name, "a+")
        cont = 0
        for line in _input_file:
        
            if cont == 0:
                _output_file.write(line)
            else:
                _output_file.write(str(cont) + ',' + line)

            cont+=1

def csv_count_col(filename, col_name) -> dict:
    chunksize = 10 ** 6

    dict_count_col = {}
    # print('[init]', filename)

    # get unique values from col
    for chunk in pd.read_csv(filename, chunksize=chunksize, sep=','):
        for i in list(dataframe_uniq_col(chunk, col_name)):
            if i not in dict_count_col:
                dict_count_col[i] = 0
            
    # count occurrences
    for chunk in pd.read_csv(filename, chunksize=chunksize, sep=','):

        res = dataframe_count_col(chunk,col_name)

        # print(res.index, res.values)

        for (ind, val) in zip(res.index, res.values):
            dict_count_col[ind] += val

    # print('[end]', filename)
    return dict_count_col

def dataframe_count_col(dataframe, coluna):
    return dataframe[coluna].value_counts()

def dataframe_uniq_col(dataframe, coluna):
    return dataframe[coluna].unique()

def extract_col_to_dataframe(pd_dataframe, coluna, match):
    nv_dataframe = pd_dataframe.loc[pd_dataframe[coluna] == match]
    return nv_dataframe


def gerar_graficos(pd_dataframe):

    # gerar gráficos para cada aplicação
    for app_name in apps_list:
        df = extract_col_to_dataframe(pd_dataframe, 'app_class', app_name)

        if (len(df) == 0):
            continue

        # boxplot: IAT, pkt_size, largura_Banda
        # dataframe_IATs = pd.DataFrame({'IAT': df['ab_mean_iat_198']})
        # seaborn_boxplot_desenhar(titulo="IAT", nome_coluna="ab_mean_iat_198", valores=df['ab_mean_iat_198'].to_frame())

        # seaborn_boxplot_desenhar(titulo="len_pkts", nome_coluna="ab_mean_data_ip_163", valores=df['ab_mean_data_ip_163'].to_frame())
        seaborn_histo_desenhar(titulo=app_name+"-len_pkts", nome_coluna="ab_mean_data_ip_163", valores=df['ab_mean_data_ip_163'].to_frame())


        # lista_bdw = pd_dataframe['bytes_per_secs'].to_frame()
        # seaborn_boxplot_desenhar(titulo="bdw", nome_coluna="bytes_per_secs", valores=lista_bdw)

        # lista_pktss = pd_dataframe['pkts_per_secs'].to_frame()
        # seaborn_boxplot_desenhar(titulo="pktss", nome_coluna="bytes_per_secs", valores=lista_pktss)


def print_appclass_as_htmltable(filename):
    print('[init]', filename)

    res = csv_count_col(filename, 'app_class')
    # print(res)
    for app_n in apps_list:
        print("|", app_n, end="")
        for app_n in apps_list:
            if app_n in res:            
                print("|",int(res[app_n]), end ="")
            else:
                print("|0", end ="")

        print('[end]', filename)


def csv_remover_outliers(input_filename, output_filename):
    chunksize = 10 ** 6
    chunkss = 0
    for chunk in pd.read_csv(input_filename, chunksize=chunksize, sep=','):
        indexOutliers = chunk[ chunk['ab_mean_data_pkt_156'] > 1500].index
        chunk.drop(indexOutliers , inplace=True)

        dataframe_to_csvfile(chunk, output_filename,True if chunkss == 0 else False, True)
        chunkss+=1    


def df_adicionar_cabeçalho(df):
    #ajustando cabeçalhos
    if "ab_tcp" in filename:
        df.columns[ab_tcp_columns]
    elif "fluxo_total_ab" in filename:
        df.columns[total_ab_columns]
    elif "fluxo_total_two_ways" in filename:
        df.columns[total_two_ways_columns]
    elif "twoways" in filename:
        df.columns[twoways_columns]
    else:
        df.columns[ab_columns]
    return


def df_max_values_column(df):

    lista_max = df.max()
    
    return lista_max 

def df_processar(df,filename):
    # remover repetidos
    df = remover_duplicados(df)

    # remover outliers
    indexOutliers = df[ df['ab_mean_data_pkt_156'] > 1500].index
    df.drop(indexOutliers , inplace=True)

    df.to_csv('2'+filename, sep=',', encoding='utf-8', index=False, header=True)


def df_normalizar(df, lista_max):
    #proto,service_class,app_class,qos_class,qtd_pkts_total,ab_mean_iat_198,ab_med_iat_197,ab_std_iat_201,ab_min_iat_195,ab_max_iat_200,ab_q1_iat_196,ab_q3_iat_199,ab_sum_iat,ab_below_mean_iat,ab_above_mean_iat,no_transitions_bulktrans_210,time_spent_in_bulk_211,duration_connection_duration_212,bulk_percent_of_time_spent_213,time_spent_idle_214,idle_percent_of_time_215,ab_bytes_per_sec,ab_mean_data_control_163,ab_med_data_control_162,ab_var_data_control_166,ab_min_data_control_160,ab_max_data_control_165,ab_q1_data_control_161,ab_q3_data_control_164,ab_mean_data_ip_163,ab_med_data_ip_162,ab_var_data_ip_166,ab_min_data_ip_160,ab_max_data_ip_165,ab_q1_data_ip_161,ab_q3_data_ip_164,ab_min_data_control_307,ab_q1_data_control_308,ab_med_data_control_309,ab_mean_data_control_310,ab_q3_data_control_311,ab_max_data_control_312,ab_var_data_control_313,ab_mean_data_pkt_156,ab_med_data_pkt_155,ab_var_data_pkt_159,ab_min_data_pkt_153,ab_max_data_pkt_158,ab_q1_data_pkt_154,ab_q3_data_pkt_157,ab_mean_header_ip_ref321,ab_med_header_ip_ref322,ab_std_header_ip_ref323,ab_min_header_ip_ref324,ab_max_header_ip_ref325,ab_q1_header_ip_ref326,ab_q3_header_ip_ref327,ab_pkts_abv_1024,ab_pays_bel_128,ab_pays_in_128_1024,ab_pkts_abv_mean,ab_pkts_bel_mean,ab_pkts_header_sum,ab_pkts_len_sum,ab_pkts_per_sec
    #ignorando os 5 indices primeiros

    # obs, normalizar nos mesmos valores para toda as bases

    lista_colunas = df.columns

    # print(lista_colunas)
    # print(len(lista_colunas), ' - ' , len(lista_max))
    # exit(0)
    for i in range(5, len(lista_colunas)):
        if lista_max[i-5] > 0:
            df[lista_colunas[i]] = df[lista_colunas[i]].div(lista_max[i-5])

    return df

def normalizar(filename):
    lista_max = None

    if "ab_10pkts" in filename:
        lista_max = ab_10pkts_max
    elif "agrupado" in filename:
        lista_max = ab_10pkts_max
    elif "ab_30pkts" in filename:
        lista_max = ab_30pkts_max
    elif "ab_50pkts" in filename:
        lista_max = ab_50pkts_max
    elif "ab_tcp_10pkts" in filename:
        lista_max = ab_tcp_10pkts_max
    elif "ab_tcp_30pkts" in filename:
        lista_max = ab_tcp_30pkts_max
    elif "ab_tcp_50pkts" in filename:
        lista_max = ab_tcp_50pkts_max
    elif "fluxo_total_ab" in filename:
        lista_max = fluxo_total_ab_max
    elif "fluxo_total_two" in filename:
        lista_max = fluxo_total_two_ways_max
    elif "twoways_10pkts" in filename:
        lista_max = twoways_10pkts_2s_max
    elif "twoways_30pkts" in filename:
        lista_max = twoways_30pkts_2s_max
    elif "twoways_50pkts" in filename:
        lista_max = twoways_50pkts_2s_max
    else:
        print("Erro")
        exit(0)

    # normalizar
    df = pd.read_csv(filename, sep=',', encoding="UTF-8")
    df = df_normalizar(df, lista_max)
            
    df.to_csv("norm_"+filename, sep=',', encoding='utf-8', index=False, header=True)

def remover_aspas(filename):

    file = open(filename)
    file_salvar = open('noaspas'+filename, 'a+')
    
    for l in file:
        file_salvar.write(l.replace("'", ""))


    file.close()
    file_salvar.close()

def full_processing_steps(filename):

    # remover duplicados
    remover_duplicados_csvfile_to_new_csvfile(filename, 'nodup_'+filename)

    # remover outliers
    csv_remover_outliers('nodup_'+filename, 'nodup_noutliers_'+filename)
    # normalizar
    normalizar('nodup_noutliers_'+filename)


def ajustar_classes(filename):
    
    file = open(filename)
    file_salvar = open('p'+filename, 'a+')
    
    for l in file:

        if "estatico" in l:
            file_salvar.write(l.replace("estatico", "video_estatico"))
        else:
            file_salvar.write(l.replace("real", "video_real"))


    file.close()
    file_salvar.close()

def agrupar(lista_files):

    file_final = open("agrupado.csv", 'a+')

    for file in lista_files:
        file = open(file)

        for l in file:
            file_final.write(l)

        file.close()


def remover_colunas(filename):
    dataframe = pd.read_csv(filename, sep=',', encoding="UTF-8")
    dataframe = dataframe.drop(columns=["host_a","host_b","a_port","b_port","id_bloco"] , axis=1, errors='ignore')

    dataframe.to_csv("agrupado2.csv", sep=',', encoding='utf-8', index=False, header=True)

if __name__ == "__main__":

    # # filename = "newab_10pkts_2s.csv"
    chunksize = 10 ** 6

    # lista_service_labels = []

    lista_files = []
    for filename in os.listdir('bases'):

        dataframe = pd.read_csv('bases/'+filename, sep=',', encoding="UTF-8")
        print(filename)
        print(dataframe['service_class'].value_counts())
            
            # remover_colunas(filename)
            
    #         lista_files.append(filename)
    
    # agrupar(lista_files)
            # remover_duplicados_csvfile_to_new_csvfile(filename, '2'+filename)
            # depois disso adicionar os headers manualmente, pois estes ficaram sem o header (foram gerados diferente -> está lá na função de enviar para a database)

# ler os dados

# gráfico dos blocos: # para cada bloco de cada classificacao -- plotar seaborn_boxplot_desenhar, histograma_desenhar, distribuição
# criar gráficos das principais métricas: 
# IAT: ab_mean_IAT_198, idle_Percent_of_time_215
# Size: ab_mean_data_pkt_156,
# Taxa: ab_bytes_per_sec, 

# transformar as features em imagens e tentar gerar novas com GAN.

# gerar gráficos para cada grupo de blocos de um fluxo -> identificar pela tupla, pegar todos os blocos de uma tupla e plotar no gráfico por ordem de id bloco.
# gerar os mesmos gráficos

# gerar gráficos de fluxo total
# identificar os valores para ab_mean_data_pkt > 1500kb, se a média for maior, remover (principalemtne essa métrica)

# Utilizar GAN ou outra estratégia para aumentar os dados das classes,

# combinar ou remover classes que não tiverem jeito.

# utilizar a minha base tbm

# comparar os resultados, com data aumengtation e sem, com a minha base e sem.

# Normalizar os valores e refazer os procedimentos.

##### Após isso, definir os modelos e realizar a classificação

### Analisar os resultados e escrever
# data.iloc[0].values()