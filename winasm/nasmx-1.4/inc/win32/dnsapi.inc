%ifndef __dnsapi_INC__
%define __dnsapi_INC__

IMPORT , DnsGetDomainName@4
IMPORT , DnsIsAMailboxType@4
IMPORT , DnsIsStatusRcode@4
IMPORT , DnsMapRcodeToStatus@4
IMPORT , DnsStatusString@4
IMPORT , DnsUnicodeToUtf8@16
IMPORT , DnsUtf8ToUnicode@16
IMPORT , Dns_ReadPacketName@28
IMPORT , Dns_ReadPacketNameAllocate@28
IMPORT , Dns_SkipPacketName@8
IMPORT , Dns_WriteDottedNameToPacket@24
IMPORT BreakRecordsIntoBlob, 12
IMPORT CombineRecordsInBlob, 8
IMPORT DnsAcquireContextHandle_A, 12
IMPORT DnsAcquireContextHandle_W, 12
IMPORT DnsAllocateRecord, 4
IMPORT DnsApiAlloc, 4
IMPORT DnsApiAllocZero, 4
IMPORT DnsApiFree, 4
IMPORT DnsApiHeapReset, 12
IMPORT DnsApiRealloc, 8
IMPORT DnsApiSetDebugGlobals, 4
IMPORT DnsAsyncRegisterHostAddrs, 40
IMPORT DnsAsyncRegisterInit, 4
IMPORT DnsAsyncRegisterTerm, 0
IMPORT DnsCopyStringEx, 20
IMPORT DnsCreateReverseNameStringForIpAddress, 4
IMPORT DnsCreateStandardDnsNameCopy, 12
IMPORT DnsCreateStringCopy, 8
IMPORT DnsDhcpRegisterHostAddrs, 40
IMPORT DnsDhcpRegisterInit, 0
IMPORT DnsDhcpRegisterTerm, 0
IMPORT DnsDhcpRemoveRegistrations, 0
IMPORT DnsDhcpSrvRegisterHostName, 48
IMPORT DnsDhcpSrvRegisterInit, 8
IMPORT DnsDhcpSrvRegisterInitialize, 4
IMPORT DnsDhcpSrvRegisterTerm, 0
IMPORT DnsDowncaseDnsNameLabel, 16
IMPORT DnsExtractRecordsFromMessage_UTF8, 12
IMPORT DnsExtractRecordsFromMessage_W, 12
IMPORT DnsFindAuthoritativeZone, 16
IMPORT DnsFlushResolverCache, 0
IMPORT DnsFlushResolverCacheEntry_A, 4
IMPORT DnsFlushResolverCacheEntry_UTF8, 4
IMPORT DnsFlushResolverCacheEntry_W, 4
IMPORT DnsFree, 8
IMPORT DnsFreeConfigStructure, 8
IMPORT DnsGetBufferLengthForStringCopy, 16
IMPORT DnsGetCacheDataTable, 4
IMPORT DnsGetDnsServerList, 4
IMPORT DnsGetLastFailedUpdateInfo, 4
IMPORT DnsGetPrimaryDomainName_A, 0
IMPORT DnsGlobals
IMPORT DnsIpv6AddressToString, 8
IMPORT DnsIpv6StringToAddress, 12
IMPORT DnsIsStringCountValidForTextType, 8
IMPORT DnsModifyRecordsInSet_A, 24
IMPORT DnsModifyRecordsInSet_UTF8, 24
IMPORT DnsModifyRecordsInSet_W, 24
IMPORT DnsNameCompareEx_A, 12
IMPORT DnsNameCompareEx_UTF8, 12
IMPORT DnsNameCompareEx_W, 12
IMPORT DnsNameCompare_A, 8
IMPORT DnsNameCompare_UTF8, 8
IMPORT DnsNameCompare_W, 8
IMPORT DnsNameCopy, 24
IMPORT DnsNameCopyAllocate, 16
IMPORT DnsNetworkInfo_CreateFromFAZ, 20
IMPORT DnsNetworkInformation_CreateFromFAZ, 16
IMPORT DnsNotifyResolver, 8
IMPORT DnsNotifyResolverClusterIp, 8
IMPORT DnsNotifyResolverEx, 16
IMPORT DnsQueryConfig, 24
IMPORT DnsQueryConfigAllocEx, 12
IMPORT DnsQueryConfigDword, 8
IMPORT DnsQueryExA, 4
IMPORT DnsQueryExUTF8, 4
IMPORT DnsQueryExW, 4
IMPORT DnsQuery_A, 24
IMPORT DnsQuery_UTF8, 24
IMPORT DnsQuery_W, 24
IMPORT DnsRecordBuild_UTF8, 28
IMPORT DnsRecordBuild_W, 28
IMPORT DnsRecordCompare, 8
IMPORT DnsRecordCopyEx, 12
IMPORT DnsRecordListFree, 8
IMPORT DnsRecordSetCompare, 16
IMPORT DnsRecordSetCopyEx, 12
IMPORT DnsRecordSetDetach, 4
IMPORT DnsRecordStringForType, 4
IMPORT DnsRecordStringForWritableType, 4
IMPORT DnsRecordTypeForName, 8
IMPORT DnsRegisterClusterAddress, 16
IMPORT DnsReleaseContextHandle, 4
IMPORT DnsRemoveRegistrations, 0
IMPORT DnsReplaceRecordSetA, 20
IMPORT DnsReplaceRecordSetUTF8, 20
IMPORT DnsReplaceRecordSetW, 20
IMPORT DnsScreenLocalAddrsForRegistration, 12
IMPORT DnsSetConfigDword, 12
IMPORT DnsStringCopyAllocateEx, 16
IMPORT DnsUpdate, 20
IMPORT DnsUpdateTest_A, 16
IMPORT DnsUpdateTest_UTF8, 16
IMPORT DnsUpdateTest_W, 16
IMPORT DnsValidateName_A, 8
IMPORT DnsValidateName_UTF8, 8
IMPORT DnsValidateName_W, 8
IMPORT DnsValidateUtf8Byte, 8
IMPORT DnsWriteQuestionToBuffer_UTF8, 24
IMPORT DnsWriteQuestionToBuffer_W, 24
IMPORT DnsWriteReverseNameStringForIpAddress, 8
IMPORT Dns_AddRecordsToMessage, 12
IMPORT Dns_AllocateMsgBuf, 4
IMPORT Dns_BuildPacket, 28
IMPORT Dns_CleanupWinsock, 0
IMPORT Dns_CloseConnection, 4
IMPORT Dns_CloseSocket, 4
IMPORT Dns_CreateMulticastSocket, 20
IMPORT Dns_CreateSocket, 12
IMPORT Dns_CreateSocketEx, 20
IMPORT Dns_FindAuthoritativeZoneLib, 16
IMPORT Dns_GetRandomXid, 4
IMPORT Dns_InitializeMsgRemoteSockaddr, 8
IMPORT Dns_InitializeWinsock, 0
IMPORT Dns_OpenTcpConnectionAndSend, 12
IMPORT Dns_ParseMessage, 20
IMPORT Dns_ParsePacketRecord, 12
IMPORT Dns_PingAdapterServers, 4
IMPORT Dns_ReadRecordStructureFromPacket, 12
IMPORT Dns_RecvTcp, 4
IMPORT Dns_ResetNetworkInfo, 4
IMPORT Dns_SendAndRecvUdp, 20
IMPORT Dns_SendEx, 12
IMPORT Dns_SetRecordDatalength, 8
IMPORT Dns_SkipToRecord, 12
IMPORT Dns_UpdateLib, 20
IMPORT Dns_UpdateLibEx, 28
IMPORT Dns_WriteQuestionToMessage, 16
IMPORT Dns_WriteRecordStructureToPacketEx, 20
IMPORT GetCurrentTimeInSeconds, 0
IMPORT HostsFile_Close, 4
IMPORT HostsFile_Open, 4
IMPORT HostsFile_ReadLine, 4
IMPORT Local_GetRecordsForLocalName, 4
IMPORT NetInfo_Build, 4
IMPORT NetInfo_Clean, 8
IMPORT NetInfo_Copy, 4
IMPORT NetInfo_Free, 4
IMPORT NetInfo_IsForUpdate, 4
IMPORT NetInfo_ResetServerPriorities, 8
IMPORT QueryDirectEx, 40
IMPORT Query_Main, 4
IMPORT Reg_GetValueEx, 28
IMPORT Reg_ReadGlobalsEx, 8
IMPORT Send_AndRecvUdpWithParam, 20
IMPORT Send_MessagePrivate, 12
IMPORT Send_OpenTcpConnectionAndSend, 12
IMPORT Socket_CacheCleanup, 0
IMPORT Socket_CacheInit, 4
IMPORT Socket_CleanupWinsock, 0
IMPORT Socket_ClearMessageSockets, 4
IMPORT Socket_CloseEx, 8
IMPORT Socket_CloseMessageSockets, 4
IMPORT Socket_Create, 20
IMPORT Socket_CreateMulticast, 20
IMPORT Socket_InitWinsock, 0
IMPORT Util_IsIp6Running, 0

%endif