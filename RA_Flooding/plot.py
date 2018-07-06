import matplotlib.pyplot as plt
import numpy as np

x = np.array(range(1,13))
y = np.random.randint(100, size=x.shape)

plt.plot(x,y)
plt.title('The number of RA packets.')
plt.tight_layout()

fig = plt.gcf()

plt.show()