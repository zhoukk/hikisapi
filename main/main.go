package main

import (
	"encoding/xml"
	"flag"
	"log"

	"github.com/zhoukk/hikisapi"
)

type DeviceInfo struct {
	XMLName         xml.Name `xml:"DeviceInfo,omitempty"`
	XMLVersion      string   `xml:"version,attr"`
	XMLNamespace    string   `xml:"xmlns,attr"`
	SubSerialNumber string   `xml:"subSerialNumber,omitempty" json:"subSerialNumber,omitempty"`
}

type FTPNotification struct {
	XMLName              xml.Name `xml:"FTPNotification,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	Id                   string   `xml:"id,omitempty"  json:"id,omitempty"`
	Enabled              bool     `xml:"enabled"  json:"enabled"`
	UseSSL               bool     `xml:"useSSL"  json:"useSSL"`
	AddressingFormatType string   `xml:"addressingFormatType,omitempty"  json:"addressingFormatType,omitempty"`
	HostName             string   `xml:"hostName,omitempty"  json:"hostName,omitempty"`
	IpAddress            string   `xml:"ipAddress,omitempty"  json:"ipAddress,omitempty"`
	IpV6Address          string   `xml:"ipV6Address,omitempty"  json:"ipV6Address,omitempty"`
	PortNo               string   `xml:"portNo,omitempty"  json:"portNo,omitempty"`
	UserName             string   `xml:"userName,omitempty"  json:"userName,omitempty"`
	Password             string   `xml:"password,omitempty"  json:"password,omitempty"`
	PassiveModeEnabled   bool     `xml:"passiveModeEnabled"  json:"passiveModeEnabled"`
	AnnoyFtp             bool     `xml:"annoyftp"  json:"annoyftp"`
	UploadPicture        bool     `xml:"uploadPicture"  json:"uploadPicture"`
	UploadVideoClip      bool     `xml:"uploadVideoClip"  json:"uploadVideoClip"`
	UploadPath           struct {
		PathDepth        int    `xml:"pathDepth"  json:"pathDepth"`
		TopDirNameRule   string `xml:"topDirNameRule,omitempty"  json:"topDirNameRule,omitempty"`
		TopDirName       string `xml:"topDirName,omitempty"  json:"topDirName,omitempty"`
		SubDirNameRule   string `xml:"subDirNameRule,omitempty"  json:"subDirNameRule,omitempty"`
		SubDirName       string `xml:"subDirName,omitempty"  json:"subDirName,omitempty"`
		ThreeDirNameRule string `xml:"threeDirNameRule,omitempty"  json:"threeDirNameRule,omitempty"`
		ThreeDirName     string `xml:"threeDirName,omitempty"  json:"threeDirName,omitempty"`
		FourDirNameRule  string `xml:"fourDirNameRule,omitempty"  json:"fourDirNameRule,omitempty"`
		FourDirName      string `xml:"fourDirName,omitempty"  json:"fourDirName,omitempty"`
	} `xml:"uploadPath,omitempty"  json:"uploadPath,omitempty"`
	PicArchivingInterval int    `xml:"picArchivingInterval"  json:"picArchivingInterval"`
	PicNameRuleType      string `xml:"picNameRuleType,omitempty"  json:"picNameRuleType,omitempty"`
	PicNamePrefix        string `xml:"picNamePrefix,omitempty"  json:"picNamePrefix,omitempty"`
	FtpPicNameRuleType   string `xml:"ftpPicNameRuleType,omitempty"  json:"ftpPicNameRuleType,omitempty"`
	FtpPicNameRule       struct {
		ItemList struct {
			Item []struct {
				ItemID        string `xml:"itemID,omitempty"  json:"itemID,omitempty"`
				ItemOrder     string `xml:"itemOrder,omitempty"  json:"itemOrder,omitempty"`
				ItemCustomStr string `xml:"itemCustomStr,omitempty"  json:"itemCustomStr,omitempty"`
			} `xml:"Item,omitempty"  json:"Item,omitempty"`
		} `xml:"ItemList,omitempty"  json:"ItemList,omitempty"`
		Delimiter string `xml:"delimiter,omitempty"  json:"delimiter,omitempty"`
		CustomStr string `xml:"customStr,omitempty"  json:"customStr,omitempty"`
	} `xml:"FtpPicNameRule,omitempty"  json:"FtpPicNameRule,omitempty"`
	UpDataType               int    `xml:"upDataType"  json:"upDataType"`
	UploadPlateEnable        bool   `xml:"uploadPlateEnable"  json:"uploadPlateEnable"`
	Site                     string `xml:"site,omitempty"  json:"site,omitempty"`
	RoadNum                  string `xml:"roadNum,omitempty"  json:"roadNum,omitempty"`
	InstrumentNum            string `xml:"instrumentNum,omitempty"  json:"instrumentNum,omitempty"`
	Direction                string `xml:"direction,omitempty"  json:"direction,omitempty"`
	DirectionDesc            string `xml:"directionDesc,omitempty"  json:"directionDesc,omitempty"`
	MonitoringInfo1          string `xml:"monitoringInfo1,omitempty"  json:"monitoringInfo1,omitempty"`
	UploadAttachedInfomation bool   `xml:"uploadAttachedInfomation"  json:"uploadAttachedInfomation"`
	BrokenNetHttp            bool   `xml:"brokenNetHttp"  json:"brokenNetHttp"`
}

type FTPNotificationList struct {
	XMLName         xml.Name          `xml:"FTPNotificationList,omitempty"`
	XMLVersion      string            `xml:"version,attr"`
	XMLNamespace    string            `xml:"xmlns,attr"`
	FTPNotification []FTPNotification `xml:"FTPNotification,omitempty" json:"FTPNotification,omitempty"`
}

type FTPTestDescription struct {
	XMLName              xml.Name `xml:"FTPTestDescription,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	UseSSL               bool     `xml:"useSSL"  json:"useSSL"`
	AddressingFormatType string   `xml:"addressingFormatType,omitempty"  json:"addressingFormatType,omitempty"`
	HostName             string   `xml:"hostName,omitempty"  json:"hostName,omitempty"`
	IpAddress            string   `xml:"ipAddress,omitempty"  json:"ipAddress,omitempty"`
	IpV6Address          string   `xml:"ipV6Address,omitempty"  json:"ipV6Address,omitempty"`
	PortNo               string   `xml:"portNo,omitempty"  json:"portNo,omitempty"`
	UserName             string   `xml:"userName,omitempty"  json:"userName,omitempty"`
	Password             string   `xml:"password,omitempty"  json:"password,omitempty"`
	PassiveModeEnabled   bool     `xml:"passiveModeEnabled"  json:"passiveModeEnabled"`
	AnnoyFtp             bool     `xml:"annoyftp"  json:"annoyftp"`
	UploadPath           struct {
		PathDepth      int    `xml:"pathDepth"  json:"pathDepth"`
		TopDirNameRule string `xml:"topDirNameRule,omitempty"  json:"topDirNameRule,omitempty"`
		TopDirName     string `xml:"topDirName,omitempty"  json:"topDirName,omitempty"`
		SubDirNameRule string `xml:"subDirNameRule,omitempty"  json:"subDirNameRule,omitempty"`
		SubDirName     string `xml:"subDirName,omitempty"  json:"subDirName,omitempty"`
	} `xml:"uploadPath,omitempty"  json:"uploadPath,omitempty"`
}

type FTPTestResult struct {
	XMLName          xml.Name `xml:"FTPTestResult,omitempty"`
	XMLVersion       string   `xml:"version,attr"`
	XMLNamespace     string   `xml:"xmlns,attr"`
	ErrorCode        int      `xml:"errorCode"  json:"errorCode"`
	ErrorDescription string   `xml:"errorDescription,omitempty"  json:"errorDescription,omitempty"`
}

type ScheduleAction struct {
	Id                      int `xml:"id,omitempty"  json:"id,omitempty"`
	ScheduleActionStartTime struct {
		DayOfWeek string `xml:"DayOfWeek,omitempty"  json:"DayOfWeek,omitempty"`
		TimeOfDay string `xml:"TimeOfDay,omitempty"  json:"TimeOfDay,omitempty"`
	} `xml:"ScheduleActionStartTime,omitempty"  json:"ScheduleActionStartTime,omitempty"`
	ScheduleActionEndTime struct {
		DayOfWeek string `xml:"DayOfWeek,omitempty"  json:"DayOfWeek,omitempty"`
		TimeOfDay string `xml:"TimeOfDay,omitempty"  json:"TimeOfDay,omitempty"`
	} `xml:"ScheduleActionEndTime,omitempty"  json:"ScheduleActionEndTime,omitempty"`
	ScheduleDSTEnable bool   `xml:"ScheduleDSTEnable"  json:"ScheduleDSTEnable"`
	Description       string `xml:"Description,omitempty"  json:"Description,omitempty"`
	Actions           struct {
		Record              bool   `xml:"Record"  json:"Record"`
		Log                 bool   `xml:"Log"  json:"Log"`
		SaveImg             bool   `xml:"SaveImg"  json:"SaveImg"`
		ActionRecordingMode string `xml:"ActionRecordingMode,omitempty"  json:"ActionRecordingMode,omitempty"`
	} `xml:"Actions,omitempty"  json:"Actions,omitempty"`
}

type ScheduleBlock struct {
	ScheduleBlockGUID string           `xml:"ScheduleBlockGUID,omitempty"  json:"ScheduleBlockGUID,omitempty"`
	ScheduleBlockType string           `xml:"ScheduleBlockType,omitempty"  json:"ScheduleBlockType,omitempty"`
	ScheduleAction    []ScheduleAction `xml:"ScheduleAction,omitempty"  json:"ScheduleAction,omitempty"`
}

type Track struct {
	XMLName              xml.Name `xml:"Track,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	Id                   int      `xml:"id"  json:"id"`
	Channel              int      `xml:"Channel"  json:"Channel"`
	Enable               bool     `xml:"Enable"  json:"Enable"`
	Description          string   `xml:"Description,omitempty"  json:"Description,omitempty"`
	TrackGUID            string   `xml:"TrackGUID,omitempty"  json:"TrackGUID,omitempty"`
	DefaultRecordingMode string   `xml:"DefaultRecordingMode,omitempty"  json:"DefaultRecordingMode,omitempty"`
	LoopEnable           string   `xml:"LoopEnable,omitempty"  json:"LoopEnable,omitempty"`
	SrcDescriptor        struct {
		SrcGUID       string `xml:"SrcGUID,omitempty"  json:"SrcGUID,omitempty"`
		SrcChannel    int    `xml:"SrcChannel"  json:"SrcChannel"`
		StreamHint    string `xml:"StreamHint,omitempty"  json:"StreamHint,omitempty"`
		SrcDriver     string `xml:"SrcDriver,omitempty"  json:"SrcDriver,omitempty"`
		SrcType       string `xml:"SrcType,omitempty"  json:"SrcType,omitempty"`
		SrcUrl        string `xml:"SrcUrl,omitempty"  json:"SrcUrl,omitempty"`
		SrcUrlMethods string `xml:"SrcUrlMethods,omitempty"  json:"SrcUrlMethods,omitempty"`
		SrcLogin      string `xml:"SrcLogin,omitempty"  json:"SrcLogin,omitempty"`
	} `xml:"SrcDescriptor,omitempty"  json:"SrcDescriptor,omitempty"`
	TrackSchedule struct {
		ScheduleBlockList struct {
			ScheduleBlock []ScheduleBlock `xml:"ScheduleBlock,omitempty"  json:"ScheduleBlock,omitempty"`
		} `xml:"ScheduleBlockList,omitempty"  json:"ScheduleBlockList,omitempty"`
	} `xml:"TrackSchedule,omitempty"  json:"TrackSchedule,omitempty"`
	CustomExtensionList struct {
		CustomExtension []struct {
			CustomExtensionName   string `xml:"CustomExtensionName,omitempty"  json:"CustomExtensionName,omitempty"`
			EnableSchedule        bool   `xml:"enableSchedule"  json:"enableSchedule"`
			SaveAudio             bool   `xml:"SaveAudio"  json:"SaveAudio"`
			PreRecordTimeSeconds  int    `xml:"PreRecordTimeSeconds"  json:"PreRecordTimeSeconds"`
			PostRecordTimeSeconds int    `xml:"PostRecordTimeSeconds"  json:"PostRecordTimeSeconds"`
		} `xml:"CustomExtension,omitempty"  json:"CustomExtension,omitempty"`
	} `xml:"CustomExtensionList,omitempty"  json:"CustomExtensionList,omitempty"`
	HolidaySchedule struct {
		ScheduleBlock ScheduleBlock `xml:"ScheduleBlock,omitempty"  json:"ScheduleBlock,omitempty"`
	} `xml:"HolidaySchedule,omitempty"  json:"HolidaySchedule,omitempty"`
	IntelligentRecord bool `xml:"IntelligentRecord"  json:"IntelligentRecord"`
	DelayTime         int  `xml:"delayTime"  json:"delayTime"`
	DurationEnabled   bool `xml:"durationEnabled"  json:"durationEnabled"`
}

type TrackList struct {
	XMLName      xml.Name `xml:"TrackList,omitempty"`
	XMLVersion   string   `xml:"version,attr"`
	XMLNamespace string   `xml:"xmlns,attr"`
	Track        []Track  `xml:"Track,omitempty"  json:"Track,omitempty"`
}

type SnapshotCapture struct {
	Enabled         bool `xml:"enabled"  json:"enabled"`
	SupportSchedule bool `xml:"supportSchedule"  json:"supportSchedule"`
	Compress        struct {
		PictureCodecType string `xml:"pictureCodecType,omitempty"  json:"pictureCodecType,omitempty"`
		PictureWidth     int    `xml:"pictureWidth"  json:"pictureWidth"`
		PictureHeight    int    `xml:"pictureHeight"  json:"pictureHeight"`
		Quality          int    `xml:"quality"  json:"quality"`
		CaptureInterval  int    `xml:"captureInterval"  json:"captureInterval"`
		CaptureNumber    int    `xml:"captureNumber"  json:"captureNumber"`
	} `xml:"compress,omitempty"  json:"compress,omitempty"`
}

type SnapshotChannel struct {
	XMLName             xml.Name        `xml:"SnapshotChannel,omitempty"`
	XMLVersion          string          `xml:"version,attr"`
	XMLNamespace        string          `xml:"xmlns,attr"`
	Id                  int             `xml:"id"  json:"id"`
	VideoInputChannelID int             `xml:"videoInputChannelID"  json:"videoInputChannelID"`
	TimingCapture       SnapshotCapture `xml:"timingCapture,omitempty"  json:"timingCapture,omitempty"`
	EventCapture        SnapshotCapture `xml:"eventCapture,omitempty"  json:"eventCapture,omitempty"`
}

type SnapshotChannelList struct {
	XMLName         xml.Name          `xml:"SnapshotChannelList,omitempty"`
	XMLVersion      string            `xml:"version,attr"`
	XMLNamespace    string            `xml:"xmlns,attr"`
	SnapshotChannel []SnapshotChannel `xml:"SnapshotChannel,omitempty"  json:"SnapshotChannel,omitempty"`
}

func main() {
	var host string
	var user string
	var pass string
	flag.StringVar(&host, "h", "192.168.1.64", "ip camera host")
	flag.StringVar(&user, "u", "admin", "ip camera username")
	flag.StringVar(&pass, "p", "123456", "ip camera password")
	flag.Parse()

	c := hikisapi.NewClient(host, user, pass)

	info := DeviceInfo{}
	err := c.Get("/ISAPI/System/deviceInfo", nil, &info)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Printf("device: %s\n", info.SubSerialNumber)
	}

	ftp := FTPNotification{}
	err = c.Get("/ISAPI/System/Network/ftp/1", nil, &ftp)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("%s %s %s\n", ftp.Id, ftp.IpAddress, ftp.UserName)
	}

	ftp.IpAddress = "192.168.1.92"
	ftp.PortNo = "2121"
	ftp.UserName = "admin"
	ftp.Password = "12345"
	ftp.UploadPicture = true

	ret := hikisapi.ResponseStatus{}
	err = c.Put("/ISAPI/System/Network/ftp/1", &ftp, &ret)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Println(ret.StatusString)
	}

	ftpTest := FTPTestDescription{}
	ftpTest.IpAddress = ftp.IpAddress
	ftpTest.UserName = ftp.UserName
	ftpTest.Password = ftp.Password
	ftpTest.PortNo = ftp.PortNo
	ftpTest.AddressingFormatType = ftp.AddressingFormatType

	ftpRet := FTPTestResult{}
	err = c.Post("/ISAPI/System/Network/ftp/test", &ftp, &ftpRet)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Println(ftpRet.ErrorDescription)
	}

	tracks := TrackList{}
	err = c.Get("/ISAPI/ContentMgmt/record/tracks", nil, &tracks)
	if err != nil {
		log.Println(err)
		// } else {
		// 	for _, track := range tracks.Track {
		// 		log.Printf("%+v\n", track)
		// 	}
	}

	track := Track{}
	err = c.Get("/ISAPI/ContentMgmt/record/tracks/103", nil, &track)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Printf("%+v\n", track)
	}

	Weeks := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

	track.TrackSchedule.ScheduleBlockList.ScheduleBlock = make([]ScheduleBlock, 1)
	track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction = make([]ScheduleAction, 7)
	for i := 0; i < 7; i++ {
		track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].Id = i + 1
		track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionStartTime.TimeOfDay = "00:00"
		track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionStartTime.DayOfWeek = Weeks[i]
		track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionEndTime.TimeOfDay = "24:00"
		track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionEndTime.DayOfWeek = Weeks[i]
	}

	err = c.Put("/ISAPI/ContentMgmt/record/tracks/103", &track, &ret)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Println(ret.StatusString)
	}

	sc := SnapshotChannel{}
	err = c.Get("/ISAPI/Snapshot/channels/1", nil, &sc)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Printf("%+v\n", sc)
	}

	sc.TimingCapture.Enabled = true
	sc.TimingCapture.SupportSchedule = true
	sc.TimingCapture.Compress.CaptureInterval = 3000
	sc.TimingCapture.Compress.Quality = 60

	err = c.Put("/ISAPI/Snapshot/channels/1", &sc, &ret)
	if err != nil {
		log.Println(err)
		// } else {
		// 	log.Println(ret.StatusString)
	}

}
