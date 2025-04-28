import pandas as pd
import numpy as np
import random
import os
import glob
import matplotlib.pyplot as plt

random.seed(0)

drop_columns = [
    "Flow ID",
    "Source IP", "Src IP",
    "Source Port", "Src Port",
    "Destination IP", "Dst IP",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk", "Fwd Byts/b Avg",
    "Fwd Avg Packets/Bulk", "Fwd Pkts/b Avg",
    "Fwd Avg Bulk Rate", "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk", "Bwd Byts/b Avg",
    "Bwd Avg Packets/Bulk", "Bwd Pkts/b Avg",
    "Bwd Avg Bulk Rate", "Bwd Blk Rate Avg",
    'Fwd Header Length.1'
]

mapper = {
    'Dst Port': 'Destination Port',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Fwd Packets Length Total',
    'Total Length of Fwd Packets': 'Fwd Packets Length Total',
    'TotLen Bwd Pkts': 'Bwd Packets Length Total',
    'Total Length of Bwd Packets': 'Bwd Packets Length Total',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length',
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Pkt Len Min': 'Packet Length Min',
    'Min Packet Length': 'Packet Length Min',
    'Pkt Len Max': 'Packet Length Max',
    'Max Packet Length': 'Packet Length Max',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'FIN Flag Cnt': 'FIN Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count',
    'URG Flag Cnt': 'URG Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count',
    'Pkt Size Avg': 'Avg Packet Size',
    'Average Packet Size': 'Avg Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init Fwd Win Bytes',
    'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
    'Init Bwd Win Byts': 'Init Bwd Win Bytes',
    'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
    'Fwd Act Data Pkts': 'Fwd Act Data Packets',
    'act_data_pkt_fwd': 'Fwd Act Data Packets',
    'Fwd Seg Size Min': 'Fwd Seg Size Min',
    'min_seg_size_forward': 'Fwd Seg Size Min'
}


def clean_dataset(dataset, filetypes=['feather']):
    for file in os.listdir(dataset):
        file_path = f"{dataset}/{file}"

        if not os.path.isfile(file_path):
            print(f"Skipping directory: {file}")
            continue

        print(f"------- {file} -------")
        df = pd.read_csv(file_path, skipinitialspace=True, encoding='latin')
        df.columns = df.columns.str.strip()

        if 'Label' not in df.columns:
            print(f"'Label' column is missing in {file} after cleaning. Available columns: {df.columns}")
            continue

        print(df["Label"].value_counts())
        print(f"Shape: {df.shape}")

        df.rename(columns=mapper, inplace=True)
        df.drop(columns=drop_columns, inplace=True, errors="ignore")
        print(df.describe())

        df['Label'].replace({'BENIGN': 'Benign'}, inplace=True)
        df['Label'] = df.Label.astype('category')

        int_col = df.select_dtypes(include='integer').columns
        df[int_col] = df[int_col].apply(pd.to_numeric, errors='coerce', downcast='integer')
        float_col = df.select_dtypes(include='float').columns
        df[float_col] = df[float_col].apply(pd.to_numeric, errors='coerce', downcast='float')
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        df.drop_duplicates(inplace=True, subset=df.columns.difference(['Label', 'Timestamp']))
        print(df["Label"].value_counts())
        print(f"Shape: {df.shape}\n")
        df.reset_index(inplace=True, drop=True)

        def plot_day(df):
            if 'Label' in df.columns:
                df['Label'].value_counts().plot(kind='bar')
                plt.title('Label Distribution')
                plt.xlabel('Labels')
                plt.ylabel('Count')
                plt.show()

        plot_day(df)

        if 'feather' in filetypes:
            df.to_feather(f'{dataset}/clean/{file}.feather')
        if 'parquet' in filetypes:
            df.to_parquet(f'{dataset}/clean/{file}.parquet', index=False)


def aggregate_data(dataset, save=True, filetype='feather'):
    all_data_list = []
    for file in glob.glob(f'{dataset}/clean/*.{filetype}'):
        print(file)
        df = pd.read_feather(file) if filetype == 'feather' else pd.read_parquet(file)
        print(df.shape)
        print(f'{df["Label"].value_counts()}\n')
        all_data_list.append(df)

    all_data = pd.concat(all_data_list, ignore_index=True)
    duplicates = all_data[all_data.duplicated(subset=all_data.columns.difference(['Label', 'Timestamp']))]
    all_data.drop(duplicates.index, axis=0, inplace=True)
    all_data.reset_index(inplace=True, drop=True)

    if save:
        malicious = all_data[all_data.Label != 'Benign'].reset_index(drop=True)
        benign = all_data[all_data.Label == 'Benign'].reset_index(drop=True)

        if filetype == 'feather':
            all_data.to_feather(f'{dataset}/clean/all_data.feather')
            malicious.to_feather(f'{dataset}/clean/all_malicious.feather')
            benign.to_feather(f'{dataset}/clean/all_benign.feather')
        if filetype == 'parquet':
            all_data.to_parquet(f'{dataset}/clean/all_data.parquet', index=False)
            malicious.to_parquet(f'{dataset}/clean/all_malicious.parquet', index=False)
            benign.to_parquet(f'{dataset}/clean/all_benign.parquet', index=False)


if __name__ == "__main__":
    dataset_path = '/Users/avinash/Documents/capstone Project/datasets'
    clean_dataset(dataset_path, filetypes=['feather', 'parquet'])
    aggregate_data(dataset_path, save=True, filetype='feather')
    aggregate_data(dataset_path, save=True, filetype='parquet')
