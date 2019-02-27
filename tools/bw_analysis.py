import pdb
import stem.descriptor.reader as reader
import stem.descriptor
from stem import Flag
import os
import cPickle as pickle
from utils import RouterStatusEntry
import datetime
from utils import NetworkStatusDocument
from utils import ServerDescriptor
import math
import numpy as np
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import sys
""" 
Part of the code has been borrowed from the TorPS
(at least a big part of parse_decriptors() below and some utils function)

"""
router_max_age = 60*60*48

def  parse_descriptors(in_dirs):
  """Parse relay decriptors and extra-info relay descriptors """
  must_be_running = False #For bandwidth analysis, we need non-running relays
  slim = True
  descriptors = {}
  for in_consensuses_dir, in_descriptors, desc_out_dir in in_dirs:
    num_descriptors = 0
    num_relays = 0
    with reader.DescriptorReader(in_descriptors, validate=True) as r:
      for desc in r:
        if desc.fingerprint not in descriptors:
          descriptors[desc.fingerprint] = {}
        #keep all descriptors and take the most adequate after, for each fingerprint
        descriptors[desc.fingerprint][timestamp(desc.published)] = desc
    #Parsing consensus now

    pathnames = []
    for dirpath, dirnames, fnames in os.walk(in_consensuses_dir):
      for fname in fnames:
        pathnames.append(os.path.join(dirpath, fname))
    pathnames.sort()
    for pathname in pathnames:
      filename = os.path.basename(pathname)
      if filename[0] == ".":
        continue
      cons_f = open(pathname, 'rb')
      descriptors_out = {}
      hibernating_statuses = [] # (time, fprint, hibernating)
      cons_valid_after = None
      cons_valid_until = None
      cons_bw_weights = None
      cons_bwweightscale = None
      cons_fresh_until = None
      relays = {}
      num_not_found = 0
      num_found = 0
      for r_stat in stem.descriptor.parse_file(cons_f, validate=True):
        #skip non-running relays if flag is set
        if must_be_running and stem.Flag.RUNNING not in r_stat.flags:
          continue
        if cons_valid_after == None:
          cons_valid_after = r_stat.document.valid_after
          valid_after_ts = timestamp(cons_valid_after)
        if cons_fresh_until == None:
          cons_fresh_until = r_stat.document.fresh_until
          fresh_until_ts = timestamp(cons_fresh_until)
        if cons_bw_weights == None:
          cons_bw_weights = r_stat.document.bandwidth_weights
        if cons_bwweightscale == None and ('bwweightscale' in r_stat.document.params):
          cons_bwweightscale = r_stat.document.params['bwweightscale']
        relays[r_stat.fingerprint] = RouterStatusEntry(r_stat.fingerprint, r_stat.nickname,\
            r_stat.flags, r_stat.bandwidth, r_stat.is_unmeasured)

        #Now lets find more recent descritors and extra-infos with this consensus

        pub_time = timestamp(r_stat.published)
        desc_time = 0
        descs_while_fresh = []
        desc_time_fresh = None
                # get all descriptors with this fingerprint
        if (r_stat.fingerprint in descriptors):
          for t,d in descriptors[r_stat.fingerprint].items():
            # update most recent desc seen before cons pubtime
            # allow pubtime after valid_after but not fresh_until
            if (valid_after_ts-t < router_max_age) and\
                (t <= pub_time) and (t > desc_time) and\
                (t <= fresh_until_ts):
                  desc_time = t
                        # store fresh-period descs for hibernation tracking
            if (t >= valid_after_ts) and \
                (t <= fresh_until_ts):
                  descs_while_fresh.append((t,d))                                
                        # find most recent hibernating stat before fresh period
                        # prefer most-recent descriptor before fresh period
                        # but use oldest after valid_after if necessary
            if (desc_time_fresh == None):
              desc_time_fresh = t
            elif (desc_time_fresh < valid_after_ts):
              if (t > desc_time_fresh) and\
                  (t <= valid_after_ts):
                    desc_time_fresh = t
            else:
              if (t < desc_time_fresh):
                desc_time_fresh = t

                # output best descriptor if found
        if (desc_time != 0):
          num_found += 1
                    # store discovered recent descriptor
          desc = descriptors[r_stat.fingerprint][desc_time]
          if slim:
            descriptors_out[r_stat.fingerprint] = \
                ServerDescriptor(desc.fingerprint, \
                desc.hibernating, desc.nickname, \
                desc.family, desc.address, \
                desc.exit_policy, desc.average_bandwidth, desc.observed_bandwidth,\
                desc.burst_bandwidth, desc.uptime)
          else:
            descriptors_out[r_stat.fingerprint] = desc

          # store hibernating statuses
          if (desc_time_fresh == None):
            raise ValueError('Descriptor error for {0}:{1}.\n Found  descriptor before published date {2}: {3}\nDid not find descriptor for initial hibernation status for fresh period starting {4}.'.format(r_stat.nickname, r_stat.fingerprint, pub_time, desc_time, valid_after_ts))
          desc = descriptors[r_stat.fingerprint][desc_time_fresh]
          cur_hibernating = desc.hibernating
          # setting initial status
          hibernating_statuses.append((0, desc.fingerprint,\
            cur_hibernating))
          if (cur_hibernating):
            print('{0}:{1} was hibernating at consenses period start'.format(desc.nickname, desc.fingerprint))
          descs_while_fresh.sort(key = lambda x: x[0])
          for (t,d) in descs_while_fresh:
            if (d.hibernating != cur_hibernating):
              cur_hibernating = d.hibernating
              hibernating_statuses.append(\
                  (t, d.fingerprint, cur_hibernating))
              if (cur_hibernating):
                print('{0}:{1} started hibernating at {2}'\
                    .format(d.nickname, d.fingerprint, t))
              else:
                print('{0}:{1} stopped hibernating at {2}'\
                    .format(d.nickname, d.fingerprint, t))
        else:
          num_not_found += 1

    # output pickled consensus, recent descriptors, and
    # hibernating status changes
      if (cons_valid_after != None) and (cons_fresh_until != None):
        if slim:
          consensus = NetworkStatusDocument(\
            cons_valid_after, cons_fresh_until, cons_bw_weights,\
            cons_bwweightscale, relays)
        hibernating_statuses.sort(key = lambda x: x[0],\
            reverse=True)
        outpath = os.path.join(desc_out_dir,\
            cons_valid_after.strftime(\
            '%Y-%m-%d-%H-%M-%S-network_state'))
        f = open(outpath, 'wb')
        pickle.dump(consensus, f, pickle.HIGHEST_PROTOCOL)
        pickle.dump(descriptors_out,f,pickle.HIGHEST_PROTOCOL)
        pickle.dump(hibernating_statuses,f,pickle.HIGHEST_PROTOCOL)
        f.close()

        print('Wrote descriptors for {0} relays.'.\
          format(num_found))
        print('Did not find descriptors for {0} relays\n'.\
          format(num_not_found))
      else:
        print('Problem parsing {0}.'.format(filename))
    #num_consensuses += 1

      cons_f.close()


def analyse_bw(network_state_files, outpath):
  """ Collect observed bandwith data 24h past to a consensus file and adver-
      tised bandwidth of all nodes in the processed consensus
      
      Compute approximation of bandwidh used for each position of each nodes
      based on relay selection probabilities
      """
  (cons_valid_afterL, cons_fresh_untilL, cons_bw_weightsL,\
    cons_bwweightscale, lira, hibernating_statusesL,\
    descriptorsL) = get_network_state(network_state_files[0])

  (cons_valid_afterM, cons_fresh_untilM, cons_bw_weightsM,\
    cons_bwweightscale, moneTor, hibernating_statusesM,\
    descriptorsM) = get_network_state(network_state_files[1])
  #cons_rel_stats should only contains two of them 
  T, G, E, D, M , guardsL, guardexitsL, middlesL, exitsL = filter_relays(lira)
  TM, GM, EM, DM, MM , guardsM, guardexitsM, middlesM, exitsM = filter_relays(moneTor)
  
  fig, ax = plt.subplots()
  width=0.35
  p1 = ax.bar(np.arange(3), [(G*cons_bw_weightsL['Wgg']/float(cons_bwweightscale))+(D*cons_bw_weightsL['Wgd']/float(cons_bwweightscale)),\
      M+(G*cons_bw_weightsL['Wmg']/float(cons_bwweightscale))+(D*cons_bw_weightsL['Wmd']/float(cons_bwweightscale)),\
          E+(D*cons_bw_weightsL['Wed']/float(cons_bwweightscale))], width, color='r')
  p2 = ax.bar(np.arange(3)+width,[(GM*cons_bw_weightsM['Wgg']/float(cons_bwweightscale))+(DM*cons_bw_weightsM['Wgd']/float(cons_bwweightscale)),\
      MM+(GM*cons_bw_weightsM['Wmg']/float(cons_bwweightscale))+(M*cons_bw_weightsM['Wmd']/float(cons_bwweightscale)),\
          EM+(DM*cons_bw_weightsM['Wed']/float(cons_bwweightscale))], width, color='b')

  plt.tight_layout()
  plt.savefig(outpath)
    
##############################################"

# UTILS FUNCTION

##############################################


def get_network_state(ns_file):

  with open(ns_file, 'r') as nsf:
    consensus = pickle.load(nsf)
    descriptors = pickle.load(nsf)
    hibernating_statuses = pickle.load(nsf)
  cons_valid_after = timestamp(consensus.valid_after)
  cons_fresh_until = timestamp(consensus.fresh_until)
  cons_bw_weights = consensus.bandwidth_weights
  if consensus.bwweightscale == None:
    cons_bwweightscale =  10000 #default value, torspec
  else:
    cons_bwweightscale = consensus.bwweightscale

  return (cons_valid_after, cons_fresh_until, cons_bw_weights,\
      cons_bwweightscale, consensus.relays, hibernating_statuses, descriptors)

def timestamp(t):
    """Returns UNIX timestamp"""
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts

def filter_relays(cons_rel_stats):
  T=G=E=D=M=0
  guards, guardexits, middles, exits = {},{},{},{}
  for fprint, rel_stat in cons_rel_stats.iteritems():
    if (Flag.RUNNING not in rel_stat.flags):
      continue
    is_guard = Flag.GUARD in rel_stat.flags
    is_exit = (Flag.EXIT in rel_stat.flags) and (Flag.BADEXIT not in rel_stat.flags)
    T += rel_stat.bandwidth            
    if is_guard and not is_exit:
      G += rel_stat.bandwidth
      guards[fprint] = rel_stat
    elif (is_exit and not is_guard):
      E += rel_stat.bandwidth
      exits[fprint] = rel_stat
    elif (is_guard and is_exit):
      D += rel_stat.bandwidth
      guardexits[fprint] = rel_stat
    else:
      M += rel_stat.bandwidth 
      middles[fprint] = rel_stat
  return T, G, E, D, M , guards, guardexits, middles, exits

if __name__ == "__main__":

  if sys.argv[1] == "process":
        #Process just one month file
    in_dirs = [(sys.argv[2], sys.argv[3], sys.argv[4])]
    parse_descriptors(in_dirs)
  elif sys.argv[1] == "analyse_bw":
    analyse_bw([sys.argv[2], sys.argv[3]], sys.argv[4])
  else:
    raise ValueError("Command %s does not exist".format(sys.argv[1]))
