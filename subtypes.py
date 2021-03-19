 # Subtypes of wireless client
from enum import IntEnum
class ManagmentFrameSubType(IntEnum):
    AssociationRequest = 0
    ReassociationRequest = 2
    ProbeRequest = 4 #Discover all available networks on specific channel
    Authentication = 11