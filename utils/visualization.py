import matplotlib.pyplot as plt

def visualize_traffic(df):
    df['protocol'].value_counts().plot(kind='bar')
    plt.title('Traffic by Protocol')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.savefig('plots/traffic_by_protocol.png')
    plt.show()
