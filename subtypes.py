 # Subtypes of wireless client
from enum import Enum
class ManagmentFrameSubType(Enum):
    AssociationRequest = 0
    ReassociationRequest = 2
    ProbeRequest = 4 #Discover all available networks on specific channel