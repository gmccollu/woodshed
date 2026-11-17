package flow

import "strconv"

// Information Elements the decoders give columns or meaning to (the IANA IPFIX
// registry; flow v9 field types use the same numbers).
const (
	ieOctetDelta             = 1
	iePacketDelta            = 2
	ieProto                  = 4
	ieToS                    = 5
	ieTCPFlags               = 6
	ieSrcPort                = 7
	ieSrcV4                  = 8
	ieSrcMaskV4              = 9
	ieInIf                   = 10
	ieDstPort                = 11
	ieDstV4                  = 12
	ieDstMaskV4              = 13
	ieOutIf                  = 14
	ieNextHopV4              = 15
	ieSrcAS                  = 16
	ieDstAS                  = 17
	ieEndUptime              = 21 // flowEndSysUpTime (v9 LAST_SWITCHED)
	ieStartUptime            = 22 // flowStartSysUpTime (v9 FIRST_SWITCHED)
	ieSrcV6                  = 27
	ieDstV6                  = 28
	ieSamplingInterval       = 34
	ieSamplingAlgorithm      = 35
	ieEngineType             = 38
	ieEngineID               = 39
	ieSamplerID              = 48
	ieSamplerMode            = 49
	ieSamplerRandomInterval  = 50
	ieVLAN                   = 58
	ieDirection              = 61
	ieNextHopV6              = 62
	ieIfName                 = 82
	ieIfDesc                 = 83
	ieOctetTotal             = 85
	iePacketTotal            = 86
	ieExporterV4             = 130
	ieExporterV6             = 131
	ieEndReason              = 136
	ieObsDomainID            = 149
	ieStartSec               = 150
	ieEndSec                 = 151
	ieStartMs                = 152
	ieEndMs                  = 153
	ieStartUs                = 154
	ieEndUs                  = 155
	ieStartNs                = 156
	ieEndNs                  = 157
	ieStartDeltaUs           = 158
	ieEndDeltaUs             = 159
	ieSysInitMs              = 160
	ieDurationMs             = 161
	ieDurationUs             = 162
	iePostNATSrcV4           = 225
	iePostNATDstV4           = 226
	iePostNAPTSrcPort        = 227
	iePostNAPTDstPort        = 228
	ieNatEvent               = 230
	ieInitiatorOctets        = 231
	ieResponderOctets        = 232
	ieFwEvent                = 233
	ieCollectionTimeMs       = 258
	iePostNATSrcV6           = 281
	iePostNATDstV6           = 282
	ieInitiatorPackets       = 298
	ieResponderPackets       = 299
	ieObsDomainName          = 300
	ieSelectorID             = 302
	ieSelectorAlgorithm      = 304
	ieSamplingPacketInterval = 305
	ieSamplingPacketSpace    = 306
	ieSamplingSize           = 309
	ieSamplingPopulation     = 310
	ieSamplingProbability    = 311
	ieObsTimeSec             = 322
	ieObsTimeMs              = 323
	ieObsTimeUs              = 324
	ieObsTimeNs              = 325
)

// Enterprise numbers with a meaning here.
const (
	// PENReverse is RFC 5103's reverse-direction enterprise number: an IE
	// under it is the reverse of the IANA IE with the same ID.
	PENReverse = 29305
	// PENDocumentation is IANA's enterprise number for documentation (RFC
	// 5612). `woodshed send` carries its run ID, sequence numbers and rule IDs
	// under it; nothing real uses it.
	PENDocumentation = 32473
)

// Flow v9 vendor-range field types (32768–65535; v9 has no enterprise
// numbers) are kept as IEKey{PEN: 0, ID: type}, the type whole, so 40003 is
// "0:40003" everywhere: records, rule_id_ies, the API. In IPFIX (the export
// file) the high bit is the enterprise bit, which RFC 7011 §3.2 says must be
// followed by an enterprise number, so such a field is written as enterprise
// bit + the low 15 bits + enterprise number 0 (VendorRangePEN), and an IPFIX
// template field with the enterprise bit and number 0 reads back as the v9
// type (decided (build, 2026-11-17), SPEC §13.4).
//
// Number 0 rather than a registered or the documentation enterprise number:
// no IPFIX exporter sends enterprise IEs under 0 (it's IANA's own reserved
// entry, not an enterprise), so a reader tells these fields apart from every
// real enterprise IE, `woodshed send`'s 32473 IEs included, and the file
// round-trips without a side table.
const VendorRangePEN = 0

// IEKey names an Information Element: enterprise number (0 for IANA) and ID.
type IEKey struct {
	PEN uint32
	ID  uint16
}

func (k IEKey) String() string {
	return strconv.FormatUint(uint64(k.PEN), 10) + ":" + strconv.FormatUint(uint64(k.ID), 10)
}

// ieNames are the IANA names of the IEs Woodshed knows, for the per-exporter
// template field list.
var ieNames = map[uint16]string{
	1: "octetDeltaCount", 2: "packetDeltaCount", 3: "deltaFlowCount", 4: "protocolIdentifier", 5: "ipClassOfService",
	6: "tcpControlBits", 7: "sourceTransportPort", 8: "sourceIPv4Address", 9: "sourceIPv4PrefixLength",
	10: "ingressInterface", 11: "destinationTransportPort", 12: "destinationIPv4Address",
	13: "destinationIPv4PrefixLength", 14: "egressInterface", 15: "ipNextHopIPv4Address", 16: "bgpSourceAsNumber",
	17: "bgpDestinationAsNumber", 18: "bgpNextHopIPv4Address", 19: "postMCastPacketDeltaCount",
	20: "postMCastOctetDeltaCount", 21: "flowEndSysUpTime", 22: "flowStartSysUpTime", 23: "postOctetDeltaCount",
	24: "postPacketDeltaCount", 25: "minimumIpTotalLength", 26: "maximumIpTotalLength", 27: "sourceIPv6Address",
	28: "destinationIPv6Address", 29: "sourceIPv6PrefixLength", 30: "destinationIPv6PrefixLength",
	31: "flowLabelIPv6", 32: "icmpTypeCodeIPv4", 33: "igmpType", 34: "samplingInterval", 35: "samplingAlgorithm",
	36: "flowActiveTimeout", 37: "flowIdleTimeout", 38: "engineType", 39: "engineId", 40: "exportedOctetTotalCount",
	41: "exportedMessageTotalCount", 42: "exportedFlowRecordTotalCount", 44: "sourceIPv4Prefix",
	45: "destinationIPv4Prefix", 46: "mplsTopLabelType", 47: "mplsTopLabelIPv4Address", 48: "samplerId",
	49: "samplerMode", 50: "samplerRandomInterval", 52: "minimumTTL", 53: "maximumTTL", 54: "fragmentIdentification",
	55: "postIpClassOfService", 56: "sourceMacAddress", 57: "postDestinationMacAddress", 58: "vlanId",
	59: "postVlanId", 60: "ipVersion", 61: "flowDirection", 62: "ipNextHopIPv6Address", 63: "bgpNextHopIPv6Address",
	64: "ipv6ExtensionHeaders", 70: "mplsTopLabelStackSection", 80: "destinationMacAddress",
	81: "postSourceMacAddress", 82: "interfaceName", 83: "interfaceDescription", 85: "octetTotalCount",
	86: "packetTotalCount", 88: "fragmentOffset", 89: "forwardingStatus", 90: "mplsVpnRouteDistinguisher",
	94: "applicationDescription", 95: "applicationId", 96: "applicationName", 98: "postIpDiffServCodePoint",
	99: "multicastReplicationFactor", 128: "bgpNextAdjacentAsNumber", 129: "bgpPrevAdjacentAsNumber",
	130: "exporterIPv4Address", 131: "exporterIPv6Address", 132: "droppedOctetDeltaCount",
	133: "droppedPacketDeltaCount", 136: "flowEndReason", 137: "commonPropertiesId", 138: "observationPointId",
	139: "icmpTypeCodeIPv6", 141: "lineCardId", 142: "portId", 143: "meteringProcessId", 144: "exportingProcessId",
	145: "templateId", 148: "flowId", 149: "observationDomainId", 150: "flowStartSeconds", 151: "flowEndSeconds",
	152: "flowStartMilliseconds", 153: "flowEndMilliseconds", 154: "flowStartMicroseconds",
	155: "flowEndMicroseconds", 156: "flowStartNanoseconds", 157: "flowEndNanoseconds",
	158: "flowStartDeltaMicroseconds", 159: "flowEndDeltaMicroseconds", 160: "systemInitTimeMilliseconds",
	161: "flowDurationMilliseconds", 162: "flowDurationMicroseconds", 176: "icmpTypeIPv4", 177: "icmpCodeIPv4",
	178: "icmpTypeIPv6", 179: "icmpCodeIPv6", 180: "udpSourcePort", 181: "udpDestinationPort",
	182: "tcpSourcePort", 183: "tcpDestinationPort", 192: "ipTTL", 195: "ipDiffServCodePoint",
	210: "paddingOctets", 225: "postNATSourceIPv4Address", 226: "postNATDestinationIPv4Address",
	227: "postNAPTSourceTransportPort", 228: "postNAPTDestinationTransportPort", 230: "natEvent",
	231: "initiatorOctets", 232: "responderOctets", 233: "firewallEvent", 234: "ingressVRFID", 235: "egressVRFID",
	239: "biflowDirection", 243: "dot1qVlanId", 252: "ingressPhysicalInterface", 253: "egressPhysicalInterface",
	258: "collectionTimeMilliseconds", 281: "postNATSourceIPv6Address", 282: "postNATDestinationIPv6Address",
	283: "natPoolId", 284: "natPoolName", 298: "initiatorPackets", 299: "responderPackets",
	300: "observationDomainName", 302: "selectorId", 304: "selectorAlgorithm", 305: "samplingPacketInterval",
	306: "samplingPacketSpace", 307: "samplingTimeInterval", 308: "samplingTimeSpace", 309: "samplingSize",
	310: "samplingPopulation", 311: "samplingProbability", 322: "observationTimeSeconds",
	323: "observationTimeMilliseconds", 324: "observationTimeMicroseconds", 325: "observationTimeNanoseconds",
	346: "privateEnterpriseNumber", 352: "layer2OctetDeltaCount", 353: "layer2OctetTotalCount",
	361: "portRangeStart", 362: "portRangeEnd", 363: "portRangeStepSize", 364: "portRangeNumPorts",
	466: "natQuotaExceededEvent", 471: "maxSessionEntries", 472: "maxBIBEntries",
}

// v9ScopeNames are flow v9's options scope field types (RFC 3954 §6.1).
var v9ScopeNames = map[uint16]string{1: "scopeSystem", 2: "scopeInterface", 3: "scopeLineCard", 4: "scopeCache",
	5: "scopeTemplate"}

// IEName is an IE's display name: the IANA name for one Woodshed knows,
// "reverse" + the name for RFC 5103's reverse IEs, else "pen:id".
func IEName(pen uint32, id uint16) string {
	switch pen {
	case 0:
		if n, ok := ieNames[id]; ok {
			return n
		}
	case PENReverse:
		if n, ok := ieNames[id]; ok {
			return "reverse" + string(n[0]-'a'+'A') + n[1:]
		}
	}
	return IEKey{pen, id}.String()
}
