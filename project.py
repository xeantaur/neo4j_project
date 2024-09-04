import json
from neo4j import GraphDatabase
from pyspark.sql import SparkSession
from pyspark.sql.functions import trim, col

# Neo4j bağlantı bilgileri
uri = "bolt://localhost:7687"
username = "neo4j"
password = "12345678"
driver = GraphDatabase.driver(uri, auth=(username, password))

# JSON dosyasını yükleme
with open('C:\\Users\\serta\\Desktop\\pcap0.json') as f:
    json_data = json.load(f)

# Alarm verilerini Neo4j'ye yükleme fonksiyonu
def load_alarm_data_to_neo4j(data):
    with driver.session() as session:
        for entry in data:
            query = """
            MERGE (src_ip:IP {address: $src_ip})
            MERGE (dst_ip:IP {address: $dst_ip})
            CREATE (src_ip)-[:ALERT {sid: $sid, gid: $gid, rev: $rev, message: $message, priority: $priority, protocol: $protocol, src_port: $src_port, dst_port: $dst_port}]->(dst_ip)
            """
            parameters = {
                'src_ip': entry.get('src_ip'),
                'dst_ip': entry.get('dst_ip'),
                'sid': entry.get('sid'),
                'gid': entry.get('gid'),
                'rev': entry.get('rev'),
                'message': entry.get('message'),
                'priority': entry.get('priority'),
                'protocol': entry.get('protocol'),
                'src_port': entry.get('src_port'),
                'dst_port': entry.get('dst_port')
            }
            session.run(query, parameters)

# Alarm verilerini Neo4j'ye yükleme
load_alarm_data_to_neo4j(json_data)

# PySpark oturumunu oluşturma
spark = SparkSession.builder \
    .appName("Network Traffic Analysis") \
    .getOrCreate()

# Tshark dosyasını PySpark DataFrame'e yükleme
csv_file_path = 'C:\\Users\\serta\\Desktop\\test.csv'
df = spark.read.csv(csv_file_path, sep="\t", header=False)

# Sütun adlarını yeniden adlandırma
df = df.toDF("eth_src_resolved", "eth_dst_resolved", "ip_src", "ip_dst", "Unnamed: 4", "Unnamed: 5", "protocol")

# Gereksiz sütunları kaldırma
df = df.drop("Unnamed: 4", "Unnamed: 5")

# Boşlukları temizleme
df = df.withColumn("eth_src_resolved", trim(col("eth_src_resolved")))
df = df.withColumn("eth_dst_resolved", trim(col("eth_dst_resolved")))
df = df.withColumn("ip_src", trim(col("ip_src")))
df = df.withColumn("ip_dst", trim(col("ip_dst")))

# Null veya boş değerleri filtreleme
df = df.filter((col("ip_src").isNotNull()) & (col("ip_dst").isNotNull()) & 
               (col("eth_src_resolved") != "") & (col("eth_dst_resolved") != ""))

# Tekrar edenleri kaldırma
df = df.dropDuplicates()

# Verileri PySpark DataFrame'den listeye dönüştürme
data_list = df.collect()

# Layer 2 veriyi Neo4j'ye yükleme fonksiyonu
def load_layer2_data_to_neo4j(data):
    with driver.session() as session:
        for row in data:
            query = """
            MERGE (src:MAC {address: $eth_src_resolved})
            MERGE (dst:MAC {address: $eth_dst_resolved})
            CREATE (src)-[:DESTINATION {protocol: $protocol}]->(dst)
            """
            parameters = {
                'eth_src_resolved': row['eth_src_resolved'],
                'eth_dst_resolved': row['eth_dst_resolved'],
                'protocol': row['protocol']
            }
            session.run(query, parameters)

# Layer 3 veriyi Neo4j'ye yükleme fonksiyonu
def load_layer3_data_to_neo4j(data):
    with driver.session() as session:
        for row in data:
            query = """
            MERGE (src_ip:IP {address: $ip_src})
            MERGE (dst_ip:IP {address: $ip_dst})
            MERGE (src_mac:MAC {address: $eth_src_resolved})
            MERGE (dst_mac:MAC {address: $eth_dst_resolved})

            CREATE (src_ip)-[:ASSOCIATED_WITH]->(src_mac)
            CREATE (dst_ip)-[:ASSOCIATED_WITH]->(dst_mac)
            CREATE (src_ip)-[:DESTINATION {protocol: $protocol}]->(dst_ip)
            """
            parameters = {
                'ip_src': row['ip_src'],
                'ip_dst': row['ip_dst'],
                'eth_src_resolved': row['eth_src_resolved'],
                'eth_dst_resolved': row['eth_dst_resolved'],
                'protocol': row['protocol']
            }
            session.run(query, parameters)

# Layer 2 veriyi Neo4j'ye yükleme
load_layer2_data_to_neo4j(data_list)

# Layer 3 veriyi Neo4j'ye yükleme
load_layer3_data_to_neo4j(data_list)

# Bağlantıyı kapatma
driver.close()
