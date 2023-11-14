package main

import (
	"flag"
	"log"
	"os"

	"github.com/zhoukk/hikisapi"
)

func main() {
	var host string
	var user string
	var pass string
	flag.StringVar(&host, "h", "192.168.1.64", "ip camera host")
	flag.StringVar(&user, "u", "admin", "ip camera username")
	flag.StringVar(&pass, "p", "123456", "ip camera password")
	flag.Parse()

	c := hikisapi.NewClient(host, user, pass)

	var device_id string

	info, err := c.NET_DVR_Login()
	if err != nil {
		log.Println(err)
	} else {
		device_id = info.SubSerialNumber
		if device_id == "" {
			device_id = info.SerialNumber[len(info.SerialNumber)-9:]
		}

		log.Printf("device: %s\n", device_id)
		log.Printf("%+v\n", info)
	}

	ftp, err := c.NET_DVR_GetFtpConfig(1)
	if err != nil {
		log.Println(err)
	} else {
		ftp.Enabled = true
		ftp.AddressingFormatType = "ipaddress"
		ftp.IpAddress = "192.168.1.100"
		ftp.PortNo = "2121"
		ftp.UserName = device_id
		ftp.Password = "123456"
		ftp.UploadPicture = true

		ret, err := c.NET_DVR_SetFtpConfig(1, ftp)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}
	}

	ftp_test := hikisapi.FTPTestDescription{}
	ftp_test.IpAddress = ftp.IpAddress
	ftp_test.UserName = ftp.UserName
	ftp_test.Password = ftp.Password
	ftp_test.PortNo = ftp.PortNo
	ftp_test.AddressingFormatType = ftp.AddressingFormatType

	ret, err := c.Net_DVR_TestFtp(&ftp_test)
	if err != nil {
		log.Println(err)
	} else {
		log.Println(ret)
	}

	track, err := c.Net_DVR_GetRecordConfig(103)
	if err != nil {
		log.Println(err)
	} else {
		Weeks := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

		track.TrackSchedule.ScheduleBlockList.ScheduleBlock = make([]hikisapi.ScheduleBlock, 1)
		track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction = make([]hikisapi.ScheduleAction, 7)
		for i := 0; i < 7; i++ {
			track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].Id = i + 1
			track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionStartTime.TimeOfDay = "00:00"
			track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionStartTime.DayOfWeek = Weeks[i]
			track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionEndTime.TimeOfDay = "24:00"
			track.TrackSchedule.ScheduleBlockList.ScheduleBlock[0].ScheduleAction[i].ScheduleActionEndTime.DayOfWeek = Weeks[i]
		}
		ret, err := c.Net_DVR_SetRecordConfig(103, track)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}
	}

	sc, err := c.Net_DVR_GetSnapshotConfig(1)
	if err != nil {
		log.Println(err)
	} else {

		sc.TimingCapture.Enabled = true
		sc.TimingCapture.SupportSchedule = true
		sc.TimingCapture.Compress.CaptureInterval = 3 * 1000
		sc.TimingCapture.Compress.Quality = 60

		ret, err := c.Net_DVR_SetSnapshotConfig(1, sc)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}
	}

	tc, err := c.Net_DVR_GetTimeConfig()
	if err != nil {
		log.Println(err)
	} else {
		tc.TimeMode = "NTP"
		ret, err := c.Net_DVR_SetTimeConfig(tc)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}
	}

	ntp, err := c.Net_DVR_GetTimeNtpConfig(1)
	if err != nil {
		log.Println(err)
	} else {
		ntp.AddressingFormatType = "hostname"
		ntp.HostName = "hik-time.ys7.com"
		ntp.PortNo = 123
		ntp.SynchronizeInterval = 60

		ret, err := c.Net_DVR_SetTimeNtpConfig(1, ntp)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}
	}

	list, err := c.Net_DVR_GetAudioChannelList()
	if err != nil {
		log.Println(err)
	} else {
		log.Println(list)
	}

	channel, err := c.Net_DVR_GetAudioChannel(1)
	if err != nil {
		log.Println(err)
	} else {
		channel.Enabled = true
		ret, err := c.Net_DVR_SetAudioChannel(1, channel)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}
	}

	// ffmpeg -i default.wav -f s16le -codec:a pcm_alaw -ac 1 -ar 8000 default.pcm
	f, err := os.Open("default.pcm")
	defer f.Close()

	session, err := c.Net_DVR_StartVoiceCom(1)
	if err != nil {
		log.Println(err)
	} else {
		log.Println(session)

		c.NET_DVR_VoiceComSendData(1, f)

		ret, err := c.NET_DVR_StopVoiceCom(1)
		if err != nil {
			log.Println(err)
		} else {
			log.Println(ret)
		}

	}

}
