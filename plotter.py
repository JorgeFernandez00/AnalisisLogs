import math

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


# load data from file
data = np.load('logs.npy', allow_pickle=True)

# convert to pandas dataframe
data = pd.DataFrame(data, columns=['priority', 'protocol_ver', 'timestamp', 'host_name', 'app_name', 'process_id', 'message_id', 'struct_data', 'message'])

# convert 2023 timestamps years to 2006
data['timestamp'] = data['timestamp'].apply(lambda x: x.replace(year=2006) if x.year == 2023 else x)


# line plot of number of logs per day
plt.figure()
data['timestamp'].groupby(data['timestamp'].dt.date).count().plot()
# legend title
plt.title('Number of logs per day')
# legend y axis
plt.ylabel('Number of logs')
# legend x axis
plt.xlabel('Date')
# x labels rotation
plt.xticks(rotation=45)
# show plot
plt.show()

# line plot of number of logs per day
# add highlighted vertical area between timestamps where log count > 2000
plt.figure()
data['timestamp'].groupby(data['timestamp'].dt.date).count().plot()
plt.axvspan('2006-01-15', '2006-03-01', color='red', alpha=0.5)

# legend title
plt.title('Number of logs per day')
# legend y axis
plt.ylabel('Number of logs')
# legend x axis
plt.xlabel('Date')
# x labels rotation
plt.xticks(rotation=45)
# prevent labels from going out of bounds
plt.tight_layout()
# legend data labels on top right, legend avxspan label on top left
plt.legend(['Number of logs', 'Suspicious activity'])
plt.show()


# line plot of number of logs per day per app
plt.figure()
data['timestamp'].groupby([data['timestamp'].dt.date, data['app_name']]).count().unstack().plot()
# legend title
plt.title('Number of logs per day per app')
# legend y axis
plt.ylabel('Number of logs')
# legend x axis
plt.xlabel('Date')
# x labels rotation
plt.xticks(rotation=45)
# prevent labels from going out of bounds
plt.tight_layout()
# legend data labels on top right
plt.legend(loc='upper right')
# show plot
plt.show()

# same as above but with log scale
plt.figure()
data['timestamp'].groupby([data['timestamp'].dt.date, data['app_name']]).count().unstack().plot(logy=True)
# legend title
plt.title('Number of logs per day per app (log scale)')
# legend y axis
plt.ylabel('Number of logs')
# legend x axis
plt.xlabel('Date')
# x labels rotation
plt.xticks(rotation=45)
# prevent labels from going out of bounds
plt.tight_layout()
# legend data labels on top right
plt.legend(loc='upper right')
# show plot
plt.show()

# circle plot of distribution of logs per app
# add percentage to parts of the pie
plt.figure()
data['app_name'].value_counts().plot(kind='pie', autopct='%1.1f%%')

# legend title
plt.title('Distribution of logs per app')
plt.show()
