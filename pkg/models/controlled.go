package models

type Controlled struct {
	EventID         string `json:"eventId"`                   // 事件唯一编号，必填
	RuleID          string `json:"ruleId"`                    // 规则ID，必填
	DeviceID        string `json:"deviceId"`                  // 监测设备编号，必填
	FoundTime       string `json:"foundTime"`                 // 发现时间，必填
	SrcIP           string `json:"srcIp"`                     // 源IP地址，必填
	SrcPort         string `json:"srcPort"`                   // 源端口，必填
	DstIP           string `json:"dstIp"`                     // 目的IP地址，必填
	DstPort         string `json:"dstPort"`                   // 目的端口，必填
	MID             string `json:"mId,omitempty"`             // 客户端主机ID，非必填
	AffectResource  string `json:"affectResource,omitempty"`  // 受攻击域名，非必填
	RuleDesc        string `json:"ruleDesc"`                  // 命中规则，必填
	PayloadLength   string `json:"payloadLength,omitempty"`   // payload数据长度，非必填
	RuleDescPackets string `json:"ruleDescPackets,omitempty"` // 命中的规则包数，非必填
	Proto           int    `json:"proto"`                     // 传输层协议，必填
	AppProto        int    `json:"appProto"`                  // 应用层协议，必填
	UserAgent       string `json:"userAgent,omitempty"`       // User-Agent，非必填
	ContentType     string `json:"contentType,omitempty"`     // Content-Type，非必填
	URL             string `json:"url,omitempty"`             // URL，非必填
	Payload         string `json:"payload,omitempty"`         // 载荷片段，非必填
	SrcIPType       int    `json:"srcIpType"`                 // 源IP类型，必填
	DstIPType       int    `json:"dstIpType"`                 // 目的IP类型，必填
	RuleSegment     string `json:"ruleSegment,omitempty"`     // payload关键片段，非必填
	UlTraffic       int    `json:"ulTraffic,omitempty"`       // 上行流量，非必填
	DlTraffic       int    `json:"dlTraffic,omitempty"`       // 下行流量，非必填
	UlPackets       int    `json:"ulPackets,omitempty"`       // 上行包数量，非必填
	DlPackets       int    `json:"dlPackets,omitempty"`       // 下行包数量，非必填
	DetailInfor     string `json:"detail_infor"`              // 规则描述信息扩展字段，必填
	MalwareSha1     string `json:"malwareSha1,omitempty"`     // 告警关联的恶意样本SHA1，非必填
	MalwareSha256   string `json:"malwareSha256,omitempty"`   // 告警关联的恶意样本SHA256，非必填
	MalwareMd5      string `json:"malwareMd5,omitempty"`      // 告警关联的恶意样本的MD5，非必填
	MalwareSM3      string `json:"malwareSM3,omitempty"`      // 恶意样本SM3，非必填
	SampleSftpFilc  string `json:"sampleSftpFilc,omitempty"`  // 样本文件路径，非必填
}
