import os, sys
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import argparse
import pdb
import csv

parser = argparse.ArgumentParser(description="Plot exit measurements")
parser.add_argument("--dir", help="Directory containing port_group_xxx files")
parser.add_argument("--time_profile", action='store_true', help="Produce the time profile graph for each of the port group we have")

if __name__ == "__main__":

    args = parser.parse_args()
    filenames = []

    for root, dirs, files in os.walk(args.dir):
        for filename in files:
            if filename[0] != '.':
                filenames.append(filename)

    if args.time_profiles:
        fig = plt.figure()
        for filename in filenames:
            with open(args.dir+'/'+filename, 'rb') as csvfile:
                reader = csv.reader(csvfile, skipinitialspace=True, delimiter=',')
                ydata = [int(x) for x in next(csvfile)]
            #Todo: improves color, linestyle and y scale (logarithmic?)
            plt.plot(range(1, len(ydata)+1), ydata)
        plt.xlabel('')
        plt.ylabel('')
        plt.legend(filenames)

    ## Todo; figureout what to do with total cells counts and time std


