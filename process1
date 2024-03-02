import os
import sys
import dpkt
import socket

workspace=sys.path[0]

class one_flow(object):
    #定义flow对象
    def __init__(self,pkt_id,timestamp,direction,pkt_length):
        #init在初始化
        self.pkt_id = pkt_id
        #得到源IP和目的IP+端口
        detailed_info = pkt_id.split("_")
        self.client_ip = detailed_info[0]
        self.client_port = int(detailed_info[1])
        self.outside_ip = detailed_info[2]
        self.outside_port = int(detailed_info[3])
        
        self.start_time = timestamp
        self.last_time = timestamp
        self.pkt_count = 1
        
        #初始化burst_list
        self.burst_list = [one_burst(timestamp, direction, pkt_length)]
    
    def update(self,timestamp,direction,pkt_length):
        self.pkt_count += 1
        #这个流的最后时间 进行更新
        self.last_time = timestamp
        
        if self.burst_list[-1].direction != direction:
            #上一个的方向和现在的方向不一样
            self.burst_list.append(one_burst(timestamp,direction,pkt_length))
        else:
            #上一个的方向和现在的方向一样
            self.burst_list[-1].update(timestamp,pkt_length)
            
class one_burst(object):
    def __init__(self,timestamp,direction,pkt_length):
        #Fixed
        self.direction = direction
        self.start_time = timestamp
        #Updatable
        self.last_time = timestamp
        self.pkt_count = 1
        self.pkt_length = pkt_length
        
    def update(self,timestamp,pkt_length):
        self.last_time = timestamp
        
        self.pkt_count += 1
        self.pkt_length += pkt_length
		
def inet_to_str(inet):
	return socket.inet_ntop(socket.AF_INET, inet)

def get_burst_based_flows(pcap):
    current_flows = dict()
    for i, (timestamp, buf) in enumerate(pcap):
        try:
            #解析数据包，从以太网帧开始
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception as e:
            print(e)
            continue
        
        #检查是不是IP数据包
        if not isinstance(eth.data, dpkt.ip.IP):
            #不是IP数据包，检查是不是SLL数据包
            eth = dpkt.sll.SLL(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
		
        #是IP数据包
        ip = eth.data
        pkt_length = ip.len
		
        #得到源IP和目的IP
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)

        #检查是不是TCP数据包
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        #得到端口信息
        tcp = ip.data
        srcport = tcp.sport
        dstport = tcp.dport
        direction = None
        
        #检查是不是443端口
        #只要ip+端口一样，就是同一个流
        if dstport == 443:
            direction = -1
            pkt_id = src_ip+"_"+str(srcport)+"_"+dst_ip+"_"+str(dstport)
        elif srcport == 443:
            direction = 1
            pkt_id = dst_ip+"_"+str(dstport)+"_"+src_ip+"_"+str(srcport)
        else:
            continue
        
        #检查是不是新的流
        if pkt_id in current_flows:
            current_flows[pkt_id].update(timestamp,direction,pkt_length)
        else:
            current_flows[pkt_id] = one_flow(pkt_id,timestamp,direction,pkt_length)

    return list(current_flows.values())

def get_flows(file):
    with open(file,"rb") as input:
        pcap = dpkt.pcap.Reader(input)
        
        all_flows = get_burst_based_flows(pcap)
        print(file, "all_flows:", len(all_flows))
        return all_flows

#生成序列数据
def generate_sequence_data(all_files_flows, output_file, label_file):    
    output_features = []
    output_labels = []
    for flow in all_files_flows:
        #每个flow的特征
        one_flow = []
        client_ip = flow.client_ip
        outside_ip = flow.outside_ip
        label = client_ip + '-' + outside_ip
        #每个flow的burst
        for index,burst in enumerate(flow.burst_list):
            #index是第几个burst
            if index != 0:
                #当前累计量 = 上一个累计量 + 当前的流量
                current_cumulative = one_flow[-1] + (burst.pkt_length * burst.direction)
                one_flow.append(current_cumulative)
            else:
                one_flow.append(burst.pkt_length * burst.direction)
        
        #将one_flow中的每个元素转换成字符串
        one_flow = [str(value) for value in one_flow]
        #将one_flow中的每个元素用逗号连接
        one_line = ",".join(one_flow)
        output_features.append(one_line)
        output_labels.append(label)
    
    write_into_files(output_features, output_file)
    write_into_files(output_labels, label_file)

def write_into_files(output_features,output_file):
    with open(output_file,"w") as write_fp:
        output_features = [value+"\n" for value in output_features]
        write_fp.writelines(output_features)

def main(input_dir, output_path, suffix):
    #Output feature files
    pcap_filedir = []
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file[-len(suffix)-1:] == '.'+suffix:
                pcap_filedir.append(os.path.join(root, file))

    files = pcap_filedir
    all_files_flows = []
    for file in files:
        try:
            flows_of_file=get_flows(file)
        except Exception as e:
            print(e)
            pass
        if flows_of_file==False:#错误记录
            print(file, "Critical Error2")
            continue
        if len(flows_of_file) <= 0:
            continue
        all_files_flows += flows_of_file
 
    generate_sequence_data(all_files_flows, output_path, output_path + '_labels')

if __name__ == "__main__":
	# 接收输入参数
    # _, input_dir, output_path, suffix = sys.argv
    
    input_dir = '../data/data/'
    output_path = '../data/data/test.csv'
    suffix = 'pcap'
    main(input_dir, output_path, suffix)
    
# python3 Feature_Extract.py "input_dir" "sequence_data_path" "ext"
# python3 get_origin_flow_data.py "sequence_data_path" "save_dir" "data_type"   

'''
统计的是tcp并且端口号是443的流量
这个代码的作用是将pcap文件转换成csv文件+label文件，两个文件是对应的
csv中的每一行是一个flow的burst的累计流量
label中的每一行是一个flow的label

首先得到flow，然后得到每个flow的burst，然后将每个burst的流量累加起来，得到一个序列
burst的划分是根据方向来的，如果方向不一样，就划分成一个新的burst
'''
