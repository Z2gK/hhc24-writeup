import pandas as pd
from matplotlib import pyplot as plt

elfhawkdata = pd.read_csv("ELF-HAWK-dump-latlong.csv")
plt.plot( elfhawkdata.longitude,elfhawkdata.latitude)
plt.show()

