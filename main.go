package univention_m_interpreterImses

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/itslearninggermany/itswizard_m_basic"
	"github.com/itslearninggermany/itswizard_m_imses"
	"github.com/jinzhu/gorm"
	"log"
	"strconv"
	"strings"
)

type univentionfile struct {
	Dn     string `json:"dn"`
	ID     string `json:"id"`
	Object struct {
		UUID               string        `json:"UUID"`
		UVMMGroup          string        `json:"UVMMGroup"`
		AdGroupType        string        `json:"adGroupType"`
		AllowedEmailGroups []interface{} `json:"allowedEmailGroups"`
		AllowedEmailUsers  []interface{} `json:"allowedEmailUsers"`
		Description        string        `json:"description"`
		GidNumber          string        `json:"gidNumber"`
		Hosts              []interface{} `json:"hosts"`
		MemberOf           []interface{} `json:"memberOf"`
		Name               string        `json:"name"`
		NestedGroup        []interface{} `json:"nestedGroup"`
		SambaGroupType     string        `json:"sambaGroupType"`
		SambaRID           string        `json:"sambaRID"`
		Users              []string      `json:"users"`
		Birthday           string        `json:"birthday"`
		//		DepartmentNumber      string        `json:"departmentNumber"`
		Disabled              string      `json:"disabled"`
		DisplayName           string      `json:"displayName"`
		EMail                 []string    `json:"e-mail"`
		Firstname             string      `json:"firstname"`
		Gecos                 string      `json:"gecos"`
		Groups                []string    `json:"groups"`
		Homedrive             string      `json:"homedrive"`
		Lastname              string      `json:"lastname"`
		Locked                string      `json:"locked"`
		LockedTime            string      `json:"lockedTime"`
		MailForwardCopyToSelf string      `json:"mailForwardCopyToSelf"`
		MailPrimaryAddress    string      `json:"mailPrimaryAddress"`
		Password              string      `json:"password"`
		Passwordexpiry        interface{} `json:"passwordexpiry"`
		PrimaryGroup          string      `json:"primaryGroup"`
		Profilepath           string      `json:"profilepath"`
		Sambahome             string      `json:"sambahome"`
		School                []string    `json:"school"`
		Scriptpath            string      `json:"scriptpath"`
		Shell                 string      `json:"shell"`
		UIDNumber             string      `json:"uidNumber"`
		Unixhome              string      `json:"unixhome"`
		UnlockTime            string      `json:"unlockTime"`
		Userexpiry            interface{} `json:"userexpiry"`
		Username              string      `json:"username"`
		UcsschoolRecordUID    string      `json:"ucsschoolRecordUID"`
		UcsschoolRole         []string    `json:"ucsschoolRole"`
		UcsschoolSourceUID    string      `json:"ucsschoolSourceUID"`
	} `json:"object"`
	UdmObjectType string `json:"udm_object_type"`
}

type univentionStruct struct {
	dbClient             *gorm.DB
	dbUniventionCrawler  *gorm.DB
	itsl                 *itswizard_m_imses.Request
	data                 univentionfile
	InstitutionID        uint
	OrganisationID       uint
	IsItAUCSAtSchoolFile bool
	schoolID             string
	IsItToDelte          bool
	IsItAPerson          bool
	PersonSyncKey        string
	PersonRole           string
	PersonFirstName      string
	PersonLastName       string
	PersonEmail          string
	PersonUsername       string
	IsItAGroup           bool
	GroupSyncKey         string
	GroupName            string
	GroupMembers         []string
	SourceID             uint
}

type UniventionLog struct {
	gorm.Model
	InstitutionID uint
	Message       string
	SourceID      uint
}

type UniventionErrorLog struct {
	gorm.Model
	InstitutionID uint
	Message       string
	SourceID      uint
}

type PersonToGroup struct {
	gorm.Model
	Username      string
	GroupID       string
	InstitutionID uint
	Success       bool
}

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////METHODS//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This methode takes a JSON File in the current folder and
// store it to the univentionfile-Struct and delete the file at the end.
func CreateUniventionFileUpdate(person itswizard_m_basic.UniventionPerson, dbClient *gorm.DB, institutionId uint, itsl *itswizard_m_imses.Request) (*univentionStruct, error) {
	p := new(univentionStruct)
	err := json.Unmarshal([]byte(person.Data), &p.data)
	p.itsl = itsl
	p.InstitutionID = institutionId
	p.dbClient = dbClient
	p.IsItAUCSAtSchoolFile = p.data.IsItAUCSAtSchoolFile()
	// Set School ID
	dn := ParseDn(p.data.Dn)
	ous := dn["ou"]
	if len(ous) != 0 {
		p.schoolID = ous[0]
	}
	// Check Group or Person
	p.IsItAGroup = p.data.IsItAGroup()
	if !p.IsItAGroup {
		p.IsItAPerson = true
	}
	p.IsItToDelte = p.data.IsItToDelete(p.IsItAGroup)
	// Persons:
	if p.IsItAPerson {
		p.PersonRole = p.data.KindOfUser()
		uids := dn["uid"]
		if len(uids) != 0 {
			p.PersonSyncKey = person.PersonSyncKey
		}
		p.PersonFirstName = p.data.Object.Firstname
		p.PersonLastName = p.data.Object.Lastname
		if len(p.data.Object.EMail) != 0 {
			p.PersonEmail = p.data.Object.EMail[0]
		}
		p.PersonUsername = person.Username
	}
	// Groups
	if p.IsItAGroup {
		p.GroupSyncKey = p.data.Object.GidNumber
		cns := dn["cn"]
		if len(cns) != 0 {
			p.GroupName = cns[0]
		}
		// get members
		for i := 0; i < len(p.data.Object.Users); i++ {
			dns := ParseDn(p.data.Object.Users[i])
			uids := dns["uid"]
			if len(uids) != 0 {
				p.GroupMembers = append(p.GroupMembers, uids[0])
			}
		}
	}
	if p.IsItAUCSAtSchoolFile {
		p.OrganisationID, err = p.SchoolGetOrImport()
	}
	return p, err
}

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////METHODS//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This methode takes a JSON File in the current folder and
// store it to the univentionfile-Struct and delete the file at the end.
func CreateUniventionFile(input string, dbClient *gorm.DB, institutionId uint, itsl *itswizard_m_imses.Request) (*univentionStruct, error) {
	p := new(univentionStruct)
	err := json.Unmarshal([]byte(input), &p.data)
	p.itsl = itsl
	p.InstitutionID = institutionId
	p.dbClient = dbClient
	p.IsItAUCSAtSchoolFile = p.data.IsItAUCSAtSchoolFile()
	// Set School ID
	dn := ParseDn(p.data.Dn)
	ous := dn["ou"]
	if len(ous) != 0 {
		p.schoolID = ous[0]
	}
	// Check Group or Person
	p.IsItAGroup = p.data.IsItAGroup()
	if !p.IsItAGroup {
		p.IsItAPerson = true
	}
	p.IsItToDelte = p.data.IsItToDelete(p.IsItAGroup)
	// Persons:
	if p.IsItAPerson {
		p.PersonRole = p.data.KindOfUser()
		uids := dn["uid"]
		if len(uids) != 0 {
			p.PersonSyncKey = uids[0]
		}
		p.PersonFirstName = p.data.Object.Firstname
		p.PersonLastName = p.data.Object.Lastname
		if len(p.data.Object.EMail) != 0 {
			p.PersonEmail = p.data.Object.EMail[0]
		}
		p.PersonUsername = p.PersonSyncKey
	}
	// Groups
	if p.IsItAGroup {
		p.GroupSyncKey = p.data.Object.GidNumber
		cns := dn["cn"]
		if len(cns) != 0 {
			p.GroupName = cns[0]
		}
		// get members
		for i := 0; i < len(p.data.Object.Users); i++ {
			dns := ParseDn(p.data.Object.Users[i])
			uids := dns["uid"]
			if len(uids) != 0 {
				p.GroupMembers = append(p.GroupMembers, uids[0])
			}
		}
	}
	if p.IsItAUCSAtSchoolFile {
		p.OrganisationID, err = p.SchoolGetOrImport()
	}
	return p, err
}

/*
Check if the the Setting has data that is
important for the connector.
*/
func (p *univentionfile) IsItAUCSAtSchoolFile() bool {
	var res bool
	if strings.Contains(p.Dn, "ou=") {
		if !p.IsItAGroup() {
			if len(p.Object.School) == 0 && p.Object.Username != "" {
				res = false
			} else {
				res = true
			}
		} else {
			res = true
		}

	}
	return res
}

/*
If the input-file is about group-context,
the result is true, otherwise it is a
person and the result is false
*/
func (p *univentionfile) IsItAGroup() bool {
	res := false
	if strings.Contains(p.Dn, "cn=groups") {
		res = true
	}
	return res
}

/*
Check if the contect of the input is to delete a person or group.
True = Group; False = Person
*/
func (p *univentionfile) IsItToDelete(groupOrPerson bool) (res bool) {
	var emptyString = ""
	res = false
	if groupOrPerson { // True >> its a group
		if p.Object.Name == emptyString {
			res = true
		}
	} else {
		if p.Object.Username == emptyString {
			res = true
		}
	}
	return
}

func (p *univentionfile) GetGroupName() string {
	dn := ParseDn(p.Dn)
	cns := dn["cn"]
	if len(cns) != 0 {
		return cns[0]
	}
	return "xxxxxxxxxx"
}

func (p *univentionfile) GetSChoolname() string {
	dn := ParseDn(p.Dn)
	if len(dn["ou"]) > 0 {
		return dn["ou"][0]
	} else {
		return "ErrorGroup"
	}
}

func (p *univentionfile) GetSChoolnameOverPrimaryGroup() string {
	dn := ParseDn(p.Object.PrimaryGroup)
	if len(dn["ou"]) > 0 {
		return dn["ou"][0]
	} else {
		return "ErrorGroup"
	}
}

/*
The UCS@School knows atm 3 kinds of user: Mitarbeiter, Lehrer and Schüler. In itslearning
Mitarbeiter and Lehrer are Staff and Schüler are Students
*/
func (p *univentionfile) KindOfUser() string {
	schoolAndRole, err := p.GetAllSchoolsAndRole()
	if err != nil {
		return "Error"
	}
	fmt.Println("KINDOFUSER", schoolAndRole)

	primeschool := p.GetSChoolnameOverPrimaryGroup()
	fmt.Println("KINDOFUSER", primeschool)

	role := schoolAndRole[primeschool]

	if role == "Instructor" {
		return "Staff"
	}

	if role == "Learner" {
		return "Student"
	}

	return role
}

/*
Returns the Groupname and the ouname
map[GROUPNAME]OUNAME
*/
func (p *univentionfile) GetAllGroupsOfPerson() (out map[string]string, err error) {
	out = make(map[string]string)
	for _, k := range p.Object.Groups {
		tmp := ParseDn(k)
		if len(tmp["ou"]) != 1 {
			errors.New("Error in Groups by" + fmt.Sprint(tmp) + "ou not 1")
			continue
		}
		if len(tmp["cn"]) < 1 {
			errors.New("Error in Groups by" + fmt.Sprint(tmp) + " cd to small")
			continue
		}
		out[tmp["cn"][0]] = tmp["ou"][0]
	}
	return
}

/*
map[OUNAME]PROFILE
*/
func (p *univentionfile) GetAllSchoolsAndRole() (out map[string]string, err error) {
	out = make(map[string]string)
	for _, k := range p.Object.UcsschoolRole {
		split := strings.Split(k, ":")
		if len(split) != 3 {
			err = errors.New("Error in the ucsschoolRole")
			return
		} else {
			if split[0] == "student" {
				out[split[2]] = "Learner"
				continue
			}
			if split[0] == "teacher" {
				out[split[2]] = "Instructor"
				continue
			}
			if split[0] == "staff" {
				out[split[2]] = "Instructor"
				continue
			}
			//Todo: Nachschauen wie die Adminbezeichnung wirklich ist
			if split[0] == "school_admin" {
				out[split[2]] = "Administrator"
				continue
			}
			if split[0] == "school_admins" {
				out[split[2]] = "Administrator"
				continue
			}
			if split[0] == "admin_school" {
				out[split[2]] = "Administrator"
				continue
			}
			if split[0] == "admin" {
				out[split[2]] = "Administrator"
				continue
			}
			if split[0] == "administrator" {
				out[split[2]] = "Administrator"
				continue
			}

			err = errors.New("Error in the ucsschoolRole")
			return
		}
	}
	return
}

/*
Check if it is a "Klasse" or "Arbeitsgruppe"
Important: It only works with Groups which are not on the domain-school tier
*/
func (p *univentionfile) IsItAClass() (res bool) {
	if strings.Contains(p.Dn, "cn=klassen") {
		res = true
	}
	return
}

/*
Checks if the group is not a klasse or arbeitsgruppe it contains all lehrer
*/
func (p *univentionfile) IsItATeacherGroup() (res bool) {
	log.Println("Checking if it is a lehrer group")
	if strings.HasPrefix(p.Dn, "cn=lehrer") {
		return true
	} else {
		return false
	}
}

/*
...
*/
func (p *univentionStruct) GetDn() []byte {
	b, err := json.Marshal(&p.data)
	if err != nil {
		log.Println(err)
	}
	return b
}

/*
Checks if the group contains all mitarbeiter
*/
func (p *univentionfile) IsItAMitarbeiterGroup() (res bool) {
	log.Println("Checking if it is a mitarbeiter group")
	if strings.HasPrefix(p.Dn, "cn=mitarbeiter") {
		return true
	} else {
		return false
	}
}

/*
Checks if the group contains all schueler
*/
func (p *univentionfile) IsItAStudentGroup() (res bool) {
	log.Println("Checking if it is a student group")
	if strings.HasPrefix(p.Dn, "cn=schueler") {
		return true
	} else {
		return false
	}
}

func ParseDn(dn string) map[string][]string {
	m := make(map[string][]string)
	reader := csv.NewReader(bytes.NewBuffer([]byte(dn)))
	line, error := reader.Read()
	if error != nil {
		log.Println(error)
	}
	for i := 0; i < len(line); i++ {
		tmp := strings.Split(line[i], "=")
		if len(tmp) >= 1 {
			x := m[tmp[0]]
			x = append(x, tmp[1])
			m[tmp[0]] = x
		}
	}
	return m
}

func (p *univentionStruct) SchoolGetOrImport() (id uint, err error) {
	orga := itswizard_m_basic.DbOrganisation15{}
	if p.dbClient.Where("univention_id = ? and institution_id = ?", p.schoolID, p.InstitutionID).Last(&orga).RecordNotFound() {
		err = p.dbClient.Save(&itswizard_m_basic.DbOrganisation15{
			Name:          p.schoolID,
			InstitutionID: p.InstitutionID,
			UniventionID:  p.schoolID,
		}).Error
		if err != nil {
			return 0, err
		}
		//Auch in itslearning erstellen!!
		// Nummer aus datenbank holen
		err := p.dbClient.Where("univention_id = ? and institution_id = ?", p.schoolID, p.InstitutionID).Last(&orga).Error
		if err != nil {
			return 0, err
		}
		resp, err := p.itsl.CreateGroup(itswizard_m_basic.DbGroup15{
			SyncID:        strconv.Itoa(int(orga.ID)),
			Name:          p.schoolID,
			ParentGroupID: "0",
		}, true)
		if err != nil {
			return 0, errors.New(resp)
		}
		return orga.ID, err
	} else {
		return orga.ID, nil
	}
}

func (p *univentionStruct) Personhandling() error {
	//delete person in db
	if p.IsItToDelte {
		resp, err := p.itsl.DeletePerson(p.PersonSyncKey)
		if err != nil {
			return errors.New(resp)
		}
	} else {
		resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
			SyncPersonKey: p.PersonSyncKey,
			FirstName:     p.PersonFirstName,
			LastName:      p.PersonLastName,
			Username:      p.PersonUsername,
			Profile:       p.PersonRole,
			Email:         p.PersonEmail,
		})
		if err != nil {
			return errors.New(resp)
		}
		role := "Learner"
		if p.PersonRole == "Staff" {
			role = "Instructor"
		}
		resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
		if err != nil {
			return errors.New(resp)
		}
		var personGroups []PersonToGroup
		err = p.dbClient.Where("institution_id = ? and username = ?", p.InstitutionID, p.PersonSyncKey).Find(&personGroups).Error
		if err != nil {
			log.Println(err)
		}
		for i := 0; i < len(personGroups); i++ {
			var grtmp itswizard_m_basic.DbGroup15
			err = p.dbClient.Where("db_institution15_id = ? and name = ?", p.InstitutionID, personGroups[i].GroupID).Find(&grtmp).Error
			if err != nil {
				log.Println(err)
			} else {
				resp, err := p.itsl.CreateMembership(grtmp.SyncID, p.PersonSyncKey, role)
				if err != nil {
					log.Println(resp)
				} else {
					p.dbClient.Delete(&personGroups[i])
				}
			}
		}
	}
	return nil
}

func (p *univentionStruct) Personhandling2(setup itswizard_m_basic.UniventionSetup, databaseOfInstitution *gorm.DB) (err error, todelte bool) {
	var errorstring string
	//delete person in db
	if p.IsItToDelte {
		resp, err := p.itsl.DeletePerson(p.PersonSyncKey)
		if err != nil {
			return errors.New(resp), false
		}
		return nil, true
	} else {
		if p.PersonFirstName == "" {
			p.PersonFirstName = "NN"
		}
		if p.PersonLastName == "" {
			p.PersonLastName = "NN"
		}
		if setup.AdminSpecification {
			if p.PersonLastName == "#Admin" {
				log.Println("ist ein Admin")
				email := p.PersonEmail
				if setup.EmailNotToSync {
					email = ""
				}
				resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
					SyncPersonKey: p.PersonSyncKey,
					FirstName:     p.PersonFirstName,
					LastName:      p.PersonLastName,
					Username:      p.PersonUsername,
					Profile:       "Administrator",
					Email:         email,
				})
				if err != nil {
					errorstring = resp
				}
				resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, "Administrator")
				if err != nil {
					errorstring = errorstring + " " + resp
				}
				/*
					err = GroupHandlingForPerson(p.data,databaseOfInstitution,p.dbClient,p.itsl)
					if err != nil {
						errorstring = errorstring + err.Error() + " GrouplHandlingForPersons"
					}
				*/
				if errorstring != "" {
					log.Println("HIER: ", errorstring)
					return errors.New(errorstring), false
				}
				return nil, false
			}
		}
		if setup.MakeStudentFirstnameToOneLetter {
			if p.PersonRole == "Student" {
				resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
					SyncPersonKey: p.PersonSyncKey,
					FirstName:     firstnameToOneLetter(p.PersonFirstName),
					LastName:      p.PersonLastName,
					Username:      p.PersonUsername,
					Profile:       p.PersonRole,
					Email:         p.PersonEmail,
				})
				if err != nil {
					errorstring = resp
				}
				role := "Learner"
				if p.PersonRole == "Staff" {
					role = "Instructor"
				}
				resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
				if err != nil {
					errorstring = errorstring + " " + resp
				}
				err = GroupHandlingForPersonUpdate(p.InstitutionID, p.PersonSyncKey, p.data, databaseOfInstitution, p.dbClient, p.itsl)
				if err != nil {
					errorstring = errorstring + " " + err.Error() + " GrouplHandlingForPersons"
				}
				if errorstring != "" {
					return errors.New(errorstring), false
				}
				return nil, false
			}
		}
		if setup.MakeTeacherFirstnameToOneLetter {
			if p.PersonRole == "Staff" {
				resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
					SyncPersonKey: p.PersonSyncKey,
					FirstName:     firstnameToOneLetter(p.PersonFirstName),
					LastName:      p.PersonLastName,
					Username:      p.PersonUsername,
					Profile:       p.PersonRole,
					Email:         p.PersonEmail,
				})
				if err != nil {
					errorstring = resp
				}
				role := "Learner"
				if p.PersonRole == "Staff" {
					role = "Instructor"
				}
				resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
				if err != nil {
					errorstring = errorstring + " " + resp
				}
				err = GroupHandlingForPersonUpdate(p.InstitutionID, p.PersonSyncKey, p.data, databaseOfInstitution, p.dbClient, p.itsl)
				if err != nil {
					errorstring = errorstring + " " + err.Error() + " GrouplHandlingForPersons"
				}
				if errorstring != "" {
					return errors.New(errorstring), false
				}
				return nil, false
			}
		}
		if setup.MakeStudentFirstnameToOneName {
			//Todo Hier abfragen nach showFullfirstname
			if p.PersonRole == "Student" {
				var tmp itswizard_m_basic.UniventionPersonFullFirstName
				if databaseOfInstitution.Where("person_sync_key = ?", p.PersonSyncKey).Last(&tmp).RecordNotFound() {
					resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
						SyncPersonKey: p.PersonSyncKey,
						FirstName:     firstnameToOneName(p.PersonFirstName),
						LastName:      p.PersonLastName,
						Username:      p.PersonUsername,
						Profile:       p.PersonRole,
						Email:         p.PersonEmail,
					})
					if err != nil {
						errorstring = resp
					}
					role := "Learner"
					if p.PersonRole == "Staff" {
						role = "Instructor"
					}
					resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
					if err != nil {
						errorstring = errorstring + " " + resp
					}
					err = GroupHandlingForPersonUpdate(p.InstitutionID, p.PersonSyncKey, p.data, databaseOfInstitution, p.dbClient, p.itsl)
					if err != nil {
						errorstring = errorstring + " " + err.Error()
					}
					if errorstring != "" {
						return errors.New(errorstring), false
					}
					return nil, false
				}
			}
		}
		if setup.MakeTeacherFirstnameToOneName {
			if p.PersonRole == "Staff" {
				var tmp itswizard_m_basic.UniventionPersonFullFirstName
				if databaseOfInstitution.Where("person_sync_key = ?", p.PersonSyncKey).Last(&tmp).RecordNotFound() {
					resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
						SyncPersonKey: p.PersonSyncKey,
						FirstName:     firstnameToOneName(p.PersonFirstName),
						LastName:      p.PersonLastName,
						Username:      p.PersonUsername,
						Profile:       p.PersonRole,
						Email:         p.PersonEmail,
					})
					if err != nil {
						errorstring = resp
					}
					role := "Learner"
					if p.PersonRole == "Staff" {
						role = "Instructor"
					}
					resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
					if err != nil {
						errorstring = errorstring + " " + resp
					}
					err = GroupHandlingForPersonUpdate(p.InstitutionID, p.PersonSyncKey, p.data, databaseOfInstitution, p.dbClient, p.itsl)
					if err != nil {
						errorstring = errorstring + err.Error()
					}
					if errorstring != "" {
						return errors.New(errorstring), false
					}
					return nil, false
				}
			}
		}

		/*
			Wenn keine Besonderheit gewollt:
		*/
		resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
			SyncPersonKey: p.PersonSyncKey,
			FirstName:     p.PersonFirstName,
			LastName:      p.PersonLastName,
			Username:      p.PersonUsername,
			Profile:       p.PersonRole,
			Email:         p.PersonEmail,
		})
		if err != nil {
			errorstring = resp
		}
		role := "Learner"
		if p.PersonRole == "Staff" {
			role = "Instructor"
		}
		//Nach seiner Globalen Rolle wird er an seiner Primärschule eingesetzt!
		resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
		if err != nil {
			errorstring = errorstring + " " + resp
		}
		// UPDATE 13.12.2021
		err = GroupHandlingForPersonUpdate(p.InstitutionID, p.PersonSyncKey, p.data, databaseOfInstitution, p.dbClient, p.itsl)
		if err != nil {
			errorstring = errorstring + " " + resp
		}
		if errorstring != "" {
			return errors.New(errorstring), false
		}
		return nil, false
	}
	//	return err,false
}

// Update vom 26.11.2021
type syncGroupForUCS struct {
	MembershipID string
	Groupname    string
	Parentgroup  string
	Class        bool //Ist es eine Klasse
}

/*
func GroupHandlingForPersonUpdate (setup itswizard_basic.UniventionSetup, univentiondata univentionfile, database *gorm.DB, dbClient *gorm.DB,itsl *imses.Request) (err error)  {
	         //[schoolname] UCSatSChoolRole
	role := make(map[string]string)
	groupMembershipInItslearning := make(map[string][]syncGroupForUCS)
	groupMembershipInUCS := make(map[string][]syncGroupForUCS)


	//1. Auslesen aller Gruppenzugehörigkeiten in itslearning:
	itsl.ReadMembershipsForPerson()



	//2. Auslesen aller Gruppenzugehörigkeiten wie in UCS erwünscht:




	//3. Löschen der Mitgliedschaften, die nicht mehr existieren



	//4. Hinzufügen der Mitgliedschaften, die neu sind
}
*/

func GroupHandlingForPersonUpdate(institutionid uint, personsynckey string, univentiondata univentionfile, database *gorm.DB, dbClient *gorm.DB, itsl *itswizard_m_imses.Request) (err error) {
	log.Println("Start: GroupHandlingForPerson")
	//Fehlende Gruppen erstellen
	err = CheckGroupsAndCreateInCase(institutionid, univentiondata, dbClient, itsl)
	if err != nil {
		log.Println("Error in CheckGroupsAndCreateInCase")
		log.Println(err)
	}
	log.Println("CheckGroupsAndCreateInCase Success")

	//Membership sammeln
	mems := itsl.ReadMembershipsForPerson(personsynckey)
	membershipInItslearning := make(map[string]bool)
	for _, membership := range mems {
		membershipInItslearning[membership.GroupID] = true
	}
	log.Println("ReadMembershipsForPerson Success")

	schoolmem, groupmem, err := GetallNewMemberships(univentiondata)
	if err != nil {
		log.Println("Problem in GetallNewMemberships")
		return
	}
	log.Println("GetallNewMemberships Success")

	membershipsInUniventionfile := make(map[string]string)
	for groupname, profile := range groupmem {
		membershipsInUniventionfile[groupname] = profile
	}

	for schoolname, profile := range schoolmem {
		var school itswizard_m_basic.DbOrganisation15
		err := dbClient.Where("name = ?  and institution_id = ?", schoolname, institutionid).Last(&school).Error
		if err != nil {
			if err.Error() == "record not found" {
				err := dbClient.Where("name = ?", strings.TrimSpace(schoolname)).Last(&school).Error
				if err != nil {
					//When the school is not found, create School
					return errors.New(err.Error() + " Didnt found school with the name (TrimSpace): " + strings.TrimSpace(schoolname))
				}
			} else {
				//When the school is not found, create School
				return errors.New(err.Error() + " Didnt found school with the name: " + schoolname)
			}
		}
		membershipsInUniventionfile[strconv.Itoa(int(school.ID))] = profile
	}
	log.Println("Läuft")

	//MembershipsToDelete
	for _, membership := range mems {
		if membershipsInUniventionfile[membership.GroupID] == "" {
			if membership.GroupID == "0" {
				continue
			}
			if membership.GroupID == "schuladmin" {
				continue
			}
			log.Println("Membership wird gelöscht: ", membership)
			resp, err := itsl.DeleteMembership(membership.ID)
			if err != nil {
				//TODO: Abbrechen???????????
				//TODO: Besser machen!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				log.Println(resp)
			}
		} else {
			if membershipsInUniventionfile[membership.GroupID] != membership.Profile {
				log.Println("Update: ", membership)
				resp, err := itsl.CreateMembership(membership.GroupID, personsynckey, membershipsInUniventionfile[membership.GroupID])
				if err != nil {
					err = errors.New(resp)
					//TODO: Abbrechen???????????
					//Todo: Besser den Error zu behandeln
					log.Println(resp)
				}
			}
		}
	}

	//MembershipToImport
	for groupsyncID, profile := range membershipsInUniventionfile {
		if !membershipInItslearning[groupsyncID] {
			log.Println("Membership wird importiert: ", groupsyncID)
			resp, err := itsl.CreateMembership(groupsyncID, personsynckey, profile)
			if err != nil {
				err = errors.New(resp)
				//TODO: Abbrechen???????????
				//Todo: Besser den Error zu behandeln
				log.Println(resp)
			}
		}
	}
	return
}

// NEU//
func GroupHandlingForPerson(institutionid uint, univentiondata univentionfile, database *gorm.DB, dbClient *gorm.DB, itsl *itswizard_m_imses.Request) (err error) {
	log.Println("Start: GroupHandlingForPerson")
	//Fehlende Gruppen erstellen
	err = CheckGroupsAndCreateInCase(institutionid, univentiondata, dbClient, itsl)
	if err != nil {
		log.Println("Error in CheckGroupsAndCreateInCase")
		log.Println(err)
	}
	log.Println("CheckGroupsAndCreateInCase Success")

	//Membership sammeln
	mems := itsl.ReadMembershipsForPerson(univentiondata.Object.Username)
	membershipInItslearning := make(map[string]bool)
	for _, membership := range mems {
		membershipInItslearning[membership.GroupID] = true
	}
	log.Println("ReadMembershipsForPerson Success")

	schoolmem, groupmem, err := GetallNewMemberships(univentiondata)
	if err != nil {
		log.Println("Problem in GetallNewMemberships")
		return
	}
	log.Println("GetallNewMemberships Success")

	membershipsInUniventionfile := make(map[string]string)
	for groupname, profile := range groupmem {
		membershipsInUniventionfile[groupname] = profile
	}

	for schoolname, profile := range schoolmem {
		var school itswizard_m_basic.DbOrganisation15
		err := dbClient.Where("name = ? and institution_id = ?", schoolname, institutionid).Last(&school).Error
		if err != nil {
			if err.Error() == "record not found" {
				err := dbClient.Where("name = ?", strings.TrimSpace(schoolname)).Last(&school).Error
				if err != nil {
					//When the school is not found, create School
					return errors.New(err.Error() + " Didnt found school with the name (TrimSpace): " + strings.TrimSpace(schoolname))
				}
			} else {
				//When the school is not found, create School
				return errors.New(err.Error() + " Didnt found school with the name: " + schoolname)
			}
		}
		membershipsInUniventionfile[strconv.Itoa(int(school.ID))] = profile
	}
	log.Println("Läuft")

	//MembershipsToDelete
	for _, membership := range mems {
		if membershipsInUniventionfile[membership.GroupID] == "" {
			if membership.GroupID == "0" {
				continue
			}
			if membership.GroupID == "schuladmin" {
				continue
			}
			log.Println("Membership wird gelöscht: ", membership)
			resp, err := itsl.DeleteMembership(membership.ID)
			if err != nil {
				//TODO: Abbrechen???????????
				//TODO: Besser machen!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				log.Println(resp)
			}
		} else {
			if membershipsInUniventionfile[membership.GroupID] != membership.Profile {
				log.Println("Update: ", membership)
				resp, err := itsl.CreateMembership(membership.GroupID, univentiondata.Object.Username, membershipsInUniventionfile[membership.GroupID])
				if err != nil {
					err = errors.New(resp)
					//TODO: Abbrechen???????????
					//Todo: Besser den Error zu behandeln
					log.Println(resp)
				}
			}
		}
	}

	//MembershipToImport
	for groupsyncID, profile := range membershipsInUniventionfile {
		if !membershipInItslearning[groupsyncID] {
			log.Println("Membership wird importiert: ", groupsyncID)
			resp, err := itsl.CreateMembership(groupsyncID, univentiondata.Object.Username, profile)
			if err != nil {
				err = errors.New(resp)
				//TODO: Abbrechen???????????
				//Todo: Besser den Error zu behandeln
				log.Println(resp)
			}
		}
	}
	return
}

func CheckGroupsAndCreateInCase(institutionid uint, univentiondata univentionfile, database *gorm.DB, itsl *itswizard_m_imses.Request) error {
	out, err := GetAllGroups(univentiondata)
	if err != nil {
		return err
	}
	for goupname, schoolname := range out {
		err = CheckIfGroupsExistAndCreateInCase(institutionid, goupname, schoolname, database, itsl)
		if err != nil {
			return err
		}
	}
	return nil
}

func CheckIfGroupsExistAndCreateInCase(institutionid uint, groupname string, schoolname string, dbClient *gorm.DB, itsl *itswizard_m_imses.Request) error {
	out := itsl.ReadGroup(groupname)
	if out.Err != nil {
		var school itswizard_m_basic.DbOrganisation15
		err := dbClient.Where("name = ?  and institution_id = ?", schoolname, institutionid).Last(&school).Error
		if err != nil {
			return errors.New(err.Error() + " In CheckIfGroupsExistAndCreate: from client db: where Name = " + schoolname + " Last school")
		}
		resp, err := itsl.CreateGroup(itswizard_m_basic.DbGroup15{
			SyncID:              groupname,
			AzureGroupID:        "",
			UniventionGroupName: groupname,
			Name:                groupname,
			ParentGroupID:       strconv.Itoa(int(school.ID)),
			Level:               0,
			IsCourse:            false,
			DbInstitution15ID:   0,
			DbOrganisation15ID:  0,
		}, false)
		if err != nil {
			return errors.New(resp)
		}
	}
	return nil
	/*
		var group itswizard_basic.UniventionGroup
		if database.Where("univention_groupname = ?", groupname).Last(&group).RecordNotFound() {

		}
	*/
	return nil
}

/*
map[OUNAME]PROFILE
*/
func GetAllSchoolsAndRole(univentiondata univentionfile) (out map[string]string, err error) {
	out = make(map[string]string)
	for _, k := range univentiondata.Object.UcsschoolRole {
		split := strings.Split(k, ":")
		if len(split) != 3 {
			err = errors.New("Error in the ucsschoolRole")
			return
		} else {
			if split[0] == "student" {
				out[split[2]] = "Learner"
				continue
			}
			if split[0] == "teacher" {
				out[split[2]] = "Instructor"
				continue
			}
			if split[0] == "staff" {
				out[split[2]] = "Instructor"
				continue
			}
			//Todo: Nachschauen wie die Adminbezeichnung wirklich ist
			if split[0] == "school_admin" {
				out[split[2]] = "Administrator"
				continue
			}
			if split[0] == "school_admins" {
				out[split[2]] = "Administrator"
				continue
			}
			if split[0] == "admin_school" {
				out[split[2]] = "Administrator"
				continue
			}
			err = errors.New("Error in the ucsschoolRole")
			return
		}
	}
	return
}

/*
map[GROUPNAME]OUNAME
*/
func GetAllGroups(univentiondata univentionfile) (out map[string]string, err error) {
	out = make(map[string]string)
	for _, k := range univentiondata.Object.Groups {
		tmp := ParseDn(k)
		if len(tmp["ou"]) != 1 {
			errors.New("Error in Groups by" + fmt.Sprint(tmp) + "ou not 1")
			return
		}
		if len(tmp["cn"]) < 1 {
			errors.New("Error in Groups by" + fmt.Sprint(tmp) + " cd to small")
			return
		}
		out[tmp["cn"][0]] = tmp["ou"][0]
	}
	return
}

/*
SCHOOL:Profil     GROUP:Profil
*/
func GetallNewMemberships(univentiondata univentionfile) (schoolmembership map[string]string, groupmembership map[string]string, err error) {
	schoolmembership = make(map[string]string)
	groupmembership = make(map[string]string)
	groups, err := GetAllGroups(univentiondata)
	if err != nil {
		return
	}
	schoolmembership, err = GetAllSchoolsAndRole(univentiondata)
	if err != nil {
		return
	}
	for groupname, schoolname := range groups {
		groupmembership[groupname] = schoolmembership[schoolname]
	}
	return
}

//NEU//

func firstnameToOneLetter(firstname string) string {
	if firstname == "" {
		return "NN"
	}
	x := strings.Fields(firstname)
	for _, v := range x[0] {
		return string(v) + "."
		break
	}
	return "NN"
}

func firstnameToOneName(firstname string) string {
	if firstname == "" {
		return "NN"
	}
	x := strings.Fields(firstname)
	return x[0]
}

func mvVornamenRegelungLehrer(vorname string) string {
	if vorname == "" {
		return "NN"
	}
	x := strings.Fields(vorname)
	for _, v := range x[0] {
		return string(v) + "."
		break
	}
	return "NN"
}

func mvVornamenRegelungSchueler(vorname string) string {
	if vorname == "" {
		return "NN"
	}
	x := strings.Fields(vorname)
	return x[0]
}

func (p *univentionStruct) PersonhandlingMV() error {
	//delete person in db
	if p.IsItToDelte {
		resp, err := p.itsl.DeletePerson(p.PersonSyncKey)
		if err != nil {
			return errors.New(resp)
		}
	} else {
		if p.PersonRole == "Staff" {
			resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
				SyncPersonKey: p.PersonSyncKey,
				FirstName:     mvVornamenRegelungLehrer(p.PersonFirstName),
				LastName:      p.PersonLastName,
				Username:      p.PersonUsername,
				Profile:       p.PersonRole,
				Email:         p.PersonEmail,
			})
			if err != nil {
				return errors.New(resp)
			}
		} else {
			resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
				SyncPersonKey: p.PersonSyncKey,
				FirstName:     mvVornamenRegelungSchueler(p.PersonFirstName),
				LastName:      p.PersonLastName,
				Username:      p.PersonUsername,
				Profile:       p.PersonRole,
				Email:         p.PersonEmail,
			})
			if err != nil {
				return errors.New(resp)
			}
		}

		role := "Learner"
		if p.PersonRole == "Staff" {
			role = "Instructor"
		}
		resp, err := p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
		if err != nil {
			return errors.New(resp)
		}
		var personGroups []PersonToGroup
		err = p.dbClient.Where("institution_id = ? and username = ?", p.InstitutionID, p.PersonSyncKey).Find(&personGroups).Error
		if err != nil {
			log.Println(err)
		}
		for i := 0; i < len(personGroups); i++ {
			var grtmp itswizard_m_basic.DbGroup15
			err = p.dbClient.Where("db_institution15_id = ? and name = ?", p.InstitutionID, personGroups[i].GroupID).Find(&grtmp).Error
			if err != nil {
				log.Println(err)
			} else {
				resp, err := p.itsl.CreateMembership(grtmp.SyncID, p.PersonSyncKey, role)
				if err != nil {
					log.Println(resp)
				} else {
					p.dbClient.Delete(&personGroups[i])
				}
			}
		}
	}
	return nil
}

func (p *univentionStruct) PersonhandlingSH() error {
	//delete person in db
	if p.IsItToDelte {
		resp, err := p.itsl.DeletePerson(p.PersonSyncKey)
		if err != nil {
			return errors.New(resp)
		}
	} else {
		if p.PersonLastName == "#Admin" {
			resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
				SyncPersonKey: p.PersonSyncKey,
				FirstName:     p.PersonFirstName,
				LastName:      p.PersonLastName,
				Username:      p.PersonUsername,
				Profile:       "Administrator",
			})
			if err != nil {
				return errors.New(resp)
			}
			resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, "Administrator")
			if err != nil {
				return errors.New(resp)
			}
			resp, err = p.itsl.CreateMembership("schuladmin", p.PersonSyncKey, "Learner")
			if err != nil {
				return errors.New(resp)
			}
			return nil
		}

		resp, err := p.itsl.CreatePerson(itswizard_m_basic.DbPerson15{
			SyncPersonKey: p.PersonSyncKey,
			FirstName:     p.PersonFirstName,
			LastName:      p.PersonLastName,
			Username:      p.PersonUsername,
			Profile:       p.PersonRole,
			Email:         "",
		})

		if err != nil {
			return errors.New(resp)
		}
		role := "Learner"
		if p.PersonRole == "Staff" {
			role = "Instructor"
		}
		resp, err = p.itsl.CreateMembership(strconv.Itoa(int(p.OrganisationID)), p.PersonSyncKey, role)
		if err != nil {
			return errors.New(resp)
		}
		var personGroups []PersonToGroup
		err = p.dbClient.Where("institution_id = ? and username = ?", p.InstitutionID, p.PersonSyncKey).Find(&personGroups).Error
		if err != nil {
			log.Println(err)
		}
		for i := 0; i < len(personGroups); i++ {
			var grtmp itswizard_m_basic.DbGroup15
			err = p.dbClient.Where("db_institution15_id = ? and name = ?", p.InstitutionID, personGroups[i].GroupID).Find(&grtmp).Error
			if err != nil {
				log.Println(err)
			} else {
				resp, err := p.itsl.CreateMembership(grtmp.SyncID, p.PersonSyncKey, role)
				if err != nil {
					log.Println(resp)
				} else {
					p.dbClient.Delete(&personGroups[i])
				}
			}
		}
	}
	return nil
}

func (p *univentionStruct) Grouphandling(allGroups []itswizard_m_basic.DbGroup15) error {
	//Group is to delete
	if p.IsItToDelte {
		exist := false
		for s := 0; s < len(allGroups); s++ {
			if allGroups[s].UniventionGroupName == p.GroupName {
				p.GroupSyncKey = allGroups[s].SyncID
				exist = true
				break
			}
		}
		if !exist {
			dbGroup := itswizard_m_basic.DbGroup15{}
			err := p.dbClient.Where("univention_group_name = ? and db_organisation15_id = ?", p.GroupName, p.OrganisationID).Last(&dbGroup).Error
			if err != nil {
				log.Println(err)
			}
			p.GroupSyncKey = dbGroup.SyncID
		}

		resp, err := p.itsl.DeleteGroup(p.GroupSyncKey)
		if err != nil {
			return errors.New(resp)
		}
	} else {
		//1. Erstellen
		resp, err := p.itsl.CreateGroup(itswizard_m_basic.DbGroup15{
			SyncID:        p.GroupSyncKey,
			Name:          p.GroupName,
			ParentGroupID: strconv.Itoa(int(p.OrganisationID)),
		}, false)
		if err != nil {
			return errors.New(resp)
		}

		groupToImport := itswizard_m_basic.DbGroup15{
			SyncID:              p.GroupSyncKey,
			UniventionGroupName: p.GroupName,
			Name:                p.GroupName,
			ParentGroupID:       "rootPointer",
			Level:               1,
			IsCourse:            false,
			DbInstitution15ID:   p.InstitutionID,
			DbOrganisation15ID:  p.OrganisationID,
		}
		exist := true
		fmt.Println("check", p.GroupName)
		for s := 0; s < len(allGroups); s++ {
			if allGroups[s].SyncID == p.GroupSyncKey {
				exist = true
				fmt.Println("gibt es schon")
				break
			}
		}
		if !exist {
			err = p.dbClient.Save(&groupToImport).Error
			if err != nil {
				log.Println(err)
			}
			allGroups = append(allGroups, groupToImport)
		}

		//2. Mitglieder auslesen
		membersImSystem, err, resp := p.itsl.ReadMembershipsForGroup(p.GroupSyncKey)
		if err != nil {
			return errors.New(resp)
		}
		fmt.Println("members im System", p.GroupSyncKey, membersImSystem)

		//3. Abgleichen
		membershipsZuLoeschen := []itswizard_m_imses.Membership{}
		membershipsHinzuzufuegen := []itswizard_m_imses.Membership{}

		//Personen die hinzugefügt werden sollen:

		for i := 0; i < len(p.GroupMembers); i++ {
			hinzu := true
			for g := 0; g < len(membersImSystem); g++ {
				if p.GroupMembers[i] == membersImSystem[g].PersonID {
					hinzu = false
					break
				}
			}
			if hinzu {
				fmt.Println("Start read Person")
				fmt.Println("Gruppe:", p.GroupName)
				fmt.Println("User:", p.GroupMembers[i])
				out := p.itsl.ReadPerson(p.GroupMembers[i])
				if out.Err != nil {
					if out.Err.Error() == "The User is not in the System" {
						p.dbClient.Save(&PersonToGroup{
							Username:      p.GroupMembers[i],
							GroupID:       p.GroupName,
							InstitutionID: p.InstitutionID,
							Success:       false,
						})
					} else {
						log.Println(err)
					}
				}

				fmt.Println("Stop read Person")
				profile := "Learner"
				if out.Person.Profile == "Staff" {
					profile = "Instructor"
				}
				membershipsHinzuzufuegen = append(membershipsHinzuzufuegen, itswizard_m_imses.Membership{
					ID:       p.GroupMembers[i] + p.GroupSyncKey,
					GroupID:  p.GroupSyncKey,
					PersonID: p.GroupMembers[i],
					Profile:  profile,
				})
			}
		}

		//Personen die gelöscht werden sollen:
		for i := 0; i < len(membersImSystem); i++ {
			weg := true
			for g := 0; g < len(p.GroupMembers); g++ {
				if p.GroupMembers[g] == membersImSystem[i].PersonID {
					weg = false
					break
				}
			}
			if weg {
				membershipsZuLoeschen = append(membershipsZuLoeschen, membersImSystem[i])
			}
		}

		//4.Mitgliedschaften löschen und hinzufügen
		for i := 0; i < len(membershipsZuLoeschen); i++ {
			if membershipsZuLoeschen[i].Profile != "Administrator" {
				resp, err := p.itsl.DeleteMembership(membershipsZuLoeschen[i].ID)
				if err != nil {
					return errors.New(resp)
				}
			}
		}
		for i := 0; i < len(membershipsHinzuzufuegen); i++ {
			resp, err := p.itsl.CreateMembership(membershipsHinzuzufuegen[i].GroupID, membershipsHinzuzufuegen[i].PersonID, membershipsHinzuzufuegen[i].Profile)
			if err != nil {
				return errors.New(resp)
			}
		}
	}
	return nil
}

/*
Check if the the Setting has data that is
important for the connector.
*/
func IsItAUCSAtSchoolFile(ucsjson string) bool {
	var data univentionfile
	err := json.Unmarshal([]byte(ucsjson), &data)
	if err != nil {
		log.Println(err)
	}
	var res bool
	if strings.Contains(data.Dn, "ou=") {
		if !IsItAGroup(ucsjson) {
			if len(data.Object.School) == 0 && data.Object.Username != "" {
				res = false
			} else {
				res = true
			}
		} else {
			res = true
		}

	}
	return res
}

/*
If the input-file is about group-context,
the result is true, otherwise it is a
person and the result is false
*/
func IsItAGroup(ucsjson string) bool {
	var data univentionfile
	err := json.Unmarshal([]byte(ucsjson), &data)
	if err != nil {
		log.Println(err)
	}
	res := false
	if strings.Contains(data.Dn, "cn=groups") {
		res = true
	}
	return res
}

func NewUniventionFile(ucsjson string) univentionfile {
	var data univentionfile
	err := json.Unmarshal([]byte(ucsjson), &data)
	if err != nil {
		log.Println(err)
	}
	return data
}

func (p *univentionfile) GetGroupSyncKey() string {
	return p.Object.GidNumber
}

func (p *univentionfile) GetPersonSyncKey() string {
	dn := ParseDn(p.Dn)
	uids := dn["uid"]
	if len(uids) != 0 {
		return uids[0]
	}
	return "xxxxxxxx"
}

/*
func (p *univentionfile) IsItAGroup () bool{
	res := false
	if strings.Contains(p.Dn, "cn=groups") {
		res = true
	}
	return res
}

func (p *univentionfile) IsItAUcsSchoolFile () bool {
	var res bool
	if strings.Contains(data.Dn, "ou=") {
		if !IsItAGroup(ucsjson) {
			if len(data.Object.School) == 0 && data.Object.Username != "" {
				res = false
			} else {
				res = true
			}
		} else {
			res = true
		}

	}
	return res
}

func (p *univentionfile) IsItAPerson () bool{
	res := false
	if strings.Contains(p.Dn, "cn=groups") {
		res = true
	}
	return !res
}
*/

func (p *univentionStruct) GrouphandlingNewGroup(allGroups []itswizard_m_basic.Group, db *gorm.DB) error {
	//Group is to delete
	if p.IsItToDelte {
		exist := false
		for s := 0; s < len(allGroups); s++ {
			if allGroups[s].UniventionGroupName == p.GroupName {
				p.GroupSyncKey = allGroups[s].GroupSyncKey
				exist = true
				break
			}
		}
		if !exist {
			dbGroup := itswizard_m_basic.Group{}
			err := db.Where("univention_group_name = ? and db_organisation15_id = ?", p.GroupName, p.OrganisationID).Last(&dbGroup).Error
			if err != nil {
				log.Println(err)
			}
			p.GroupSyncKey = dbGroup.GroupSyncKey
		}

		resp, err := p.itsl.DeleteGroup(p.GroupSyncKey)
		if err != nil {
			return errors.New(resp)
		}
		return nil
	}

	//1. Erstellen
	resp, err := p.itsl.CreateGroupNewGroup(itswizard_m_basic.Group{
		GroupSyncKey:  p.GroupSyncKey,
		Name:          p.GroupName,
		ParentGroupID: strconv.Itoa(int(p.OrganisationID)),
	}, false)
	if err != nil {
		return errors.New(resp)
	}

	groupToImport := itswizard_m_basic.Group{
		GroupSyncKey:        p.GroupSyncKey,
		UniventionGroupName: p.GroupName,
		Name:                p.GroupName,
		ParentGroupID:       "rootPointer",
		IsCourse:            false,
		Institution15:       p.InstitutionID,
		Organisation15:      p.OrganisationID,
	}
	exist := false
	fmt.Println("check", p.GroupName)
	for s := 0; s < len(allGroups); s++ {
		if allGroups[s].GroupSyncKey == p.GroupSyncKey {
			exist = true
			fmt.Println("gibt es schon")
			break
		}
	}
	if !exist {
		fmt.Println("gibt es nicht nicht")
		err = db.Save(&groupToImport).Error
		fmt.Println(err)
		if err != nil {
			log.Println(err)
		}
		allGroups = append(allGroups, groupToImport)
	}

	//2. Mitglieder auslesen
	membersImSystem, err, resp := p.itsl.ReadMembershipsForGroup(p.GroupSyncKey)
	if err != nil {
		return errors.New(resp)
	}
	fmt.Println("members im System", p.GroupSyncKey, membersImSystem)

	//3. Abgleichen
	membershipsZuLoeschen := []itswizard_m_imses.Membership{}
	membershipsHinzuzufuegen := []itswizard_m_imses.Membership{}

	//Personen die hinzugefügt werden sollen:

	for i := 0; i < len(p.GroupMembers); i++ {
		hinzu := true
		for g := 0; g < len(membersImSystem); g++ {
			if p.GroupMembers[i] == membersImSystem[g].PersonID {
				hinzu = false
				break
			}
		}
		if hinzu {
			fmt.Println("Start read Person")
			fmt.Println("Gruppe:", p.GroupName)
			fmt.Println("User:", p.GroupMembers[i])
			out := p.itsl.ReadPerson(p.GroupMembers[i])
			if out.Err != nil {
				if out.Err.Error() == "The User is not in the System" {
					return errors.New(out.Err.Error() + " : " + p.GroupMembers[i])
				} else {
					log.Println(err)
				}
			}

			fmt.Println("Stop read Person")
			profile := "Learner"
			if out.Person.Profile == "Staff" {
				profile = "Instructor"
			}
			membershipsHinzuzufuegen = append(membershipsHinzuzufuegen, itswizard_m_imses.Membership{
				ID:       p.GroupMembers[i] + p.GroupSyncKey,
				GroupID:  p.GroupSyncKey,
				PersonID: p.GroupMembers[i],
				Profile:  profile,
			})
		}
	}

	//Personen die gelöscht werden sollen:
	for i := 0; i < len(membersImSystem); i++ {
		weg := true
		for g := 0; g < len(p.GroupMembers); g++ {
			if p.GroupMembers[g] == membersImSystem[i].PersonID {
				weg = false
				break
			}
		}
		if weg {
			membershipsZuLoeschen = append(membershipsZuLoeschen, membersImSystem[i])
		}
	}

	//4.Mitgliedschaften löschen und hinzufügen
	for i := 0; i < len(membershipsZuLoeschen); i++ {
		if membershipsZuLoeschen[i].Profile != "Administrator" {
			resp, err := p.itsl.DeleteMembership(membershipsZuLoeschen[i].ID)
			if err != nil {
				return errors.New(resp + " :: " + fmt.Sprint(membershipsZuLoeschen[i]))
			}
		}
	}
	for i := 0; i < len(membershipsHinzuzufuegen); i++ {
		resp, err := p.itsl.CreateMembership(membershipsHinzuzufuegen[i].GroupID, membershipsHinzuzufuegen[i].PersonID, membershipsHinzuzufuegen[i].Profile)
		if err != nil {
			return errors.New(resp + " :: " + fmt.Sprint(membershipsZuLoeschen[i]))
		}
	}
	return nil
}

func (p *univentionStruct) Grouphandling2(groupSyncKey string, institutionID uint, allDatabases map[string]*gorm.DB) (err error, todelete bool) {
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		S       string   `xml:"s,attr"`
		U       string   `xml:"u,attr"`
		Header  struct {
			Text                   string `xml:",chardata"`
			SyncResponseHeaderInfo struct {
				Text              string `xml:",chardata"`
				H                 string `xml:"h,attr"`
				Xmlns             string `xml:"xmlns,attr"`
				Xsi               string `xml:"xsi,attr"`
				Xsd               string `xml:"xsd,attr"`
				MessageIdentifier string `xml:"messageIdentifier"`
				StatusInfo        struct {
					Text      string `xml:",chardata"`
					CodeMajor string `xml:"codeMajor"`
					Severity  string `xml:"severity"`
					CodeMinor struct {
						Text           string `xml:",chardata"`
						CodeMinorField struct {
							Text           string `xml:",chardata"`
							CodeMinorName  string `xml:"codeMinorName"`
							CodeMinorValue string `xml:"codeMinorValue"`
						} `xml:"codeMinorField"`
					} `xml:"codeMinor"`
					MessageIdRef string `xml:"messageIdRef"`
					Description  struct {
						Chardata string `xml:",chardata"`
						Language struct {
							Text  string `xml:",chardata"`
							Xmlns string `xml:"xmlns,attr"`
						} `xml:"language"`
						Text struct {
							Text  string `xml:",chardata"`
							Xmlns string `xml:"xmlns,attr"`
						} `xml:"text"`
					} `xml:"description"`
				} `xml:"statusInfo"`
			} `xml:"syncResponseHeaderInfo"`
			Security struct {
				Text           string `xml:",chardata"`
				MustUnderstand string `xml:"mustUnderstand,attr"`
				O              string `xml:"o,attr"`
				Timestamp      struct {
					Text    string `xml:",chardata"`
					ID      string `xml:"Id,attr"`
					Created string `xml:"Created"`
					Expires string `xml:"Expires"`
				} `xml:"Timestamp"`
			} `xml:"Security"`
		} `xml:"Header"`
		Body struct {
			Text                     string `xml:",chardata"`
			Xsi                      string `xml:"xsi,attr"`
			Xsd                      string `xml:"xsd,attr"`
			CreateMembershipResponse struct {
				Text  string `xml:",chardata"`
				Xmlns string `xml:"xmlns,attr"`
			} `xml:"createMembershipResponse"`
		} `xml:"Body"`
	}

	type ErrorResultat struct {
		Problem               string
		InfectedGroupOrPerson string
	}

	var ercol []ErrorResultat
	//Group is to delete
	if p.IsItToDelte {
		resp, err := p.itsl.DeleteGroup(groupSyncKey)
		if err != nil {
			var tmp Envelope
			err = xml.Unmarshal([]byte(resp), &tmp)
			if err != nil {
				log.Println(err)
			}
			ercol = append(ercol, ErrorResultat{
				Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
				InfectedGroupOrPerson: p.GroupName,
			})
			b, err := json.Marshal(ercol)
			if err != nil {
				log.Println(err)
			}
			log.Println("Error:", string(b))
			return errors.New(string(b)), false
		}
		/*
			TODO TODO TODO TODO
			Todo: was passiert, wenn eine Domaingroup gelöscht wird
		*/
		if strings.HasPrefix(p.GroupName, "Domain Users") {
			log.Println("Domain Gruppe wird gelöscht")
		}
		return nil, true
	} else {
		//1. Erstellen
		resp, err := p.itsl.CreateGroup(itswizard_m_basic.DbGroup15{
			SyncID:        p.GroupSyncKey,
			Name:          p.GroupName,
			ParentGroupID: strconv.Itoa(int(p.OrganisationID)),
		}, false)
		if err != nil {
			var tmp Envelope
			err = xml.Unmarshal([]byte(resp), &tmp)
			if err != nil {
				fmt.Println(err)
			}
			ercol = append(ercol, ErrorResultat{
				Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
				InfectedGroupOrPerson: p.GroupName,
			})
			b, err := json.Marshal(ercol)
			if err != nil {
				log.Println(err)
			}
			log.Println("Error:", string(b))
			return errors.New(string(b)), false
		}

		//2. Mitglieder auslesen
		membersImSystem, err, resp := p.itsl.ReadMembershipsForGroup(p.GroupSyncKey)
		if err != nil {
			err = errors.New(resp)
			return err, false
		}
		log.Println(membersImSystem)
		log.Println("#############")

		usersInSystemMap := make(map[string]bool)
		for _, k := range membersImSystem {
			if k.PersonID == "itslearning_support" {
				continue
			}
			if k.PersonID == "itslearning_services" {
				continue
			}
			if k.PersonID == "" {
				continue
			}
			usersInSystemMap[strings.ToLower(k.PersonID)] = true
		}
		membershipIdsInSystemMap := make(map[string]itswizard_m_imses.Membership)
		for _, k := range membersImSystem {
			k.PersonID = strings.ToLower(k.PersonID)
			membershipIdsInSystemMap[strings.ToLower(k.PersonID)] = k
		}
		userToSync := make(map[string]bool)
		for _, k := range p.GroupMembers {
			userToSync[strings.ToLower(k)] = true
		}

		log.Println(usersInSystemMap)
		log.Println("+++++")
		log.Println(userToSync)
		log.Println("+++++")

		// Zu löschen
		for userid, _ := range usersInSystemMap {
			if !userToSync[userid] {
				log.Println("löschen", userid)
				resp, err := p.itsl.DeleteMembership(membershipIdsInSystemMap[userid].ID)
				if err != nil {
					var tmp Envelope
					err = xml.Unmarshal([]byte(resp), &tmp)
					if err != nil {
						log.Println(err)
					}
					ercol = append(ercol, ErrorResultat{
						Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
						InfectedGroupOrPerson: membershipIdsInSystemMap[userid].ID,
					})
				}
			}
		}
		//hinzufügen
		for userid, _ := range userToSync {
			if !usersInSystemMap[userid] {
				log.Println("hinzufügen", userid)
				var person itswizard_m_basic.UniventionPerson
				err = allDatabases[strconv.Itoa(int(institutionID))].Where("person_sync_key = ?", userid).Or("person_sync_key = ?", strings.ToLower(userid)).Last(&person).Error
				if err != nil {
					log.Println(err, userid)
					ercol = append(ercol, ErrorResultat{
						Problem:               "User not in itswizard Database",
						InfectedGroupOrPerson: userid,
					})
					/*
						out := p.itsl.ReadPerson(userid)
						log.Println("read Person", userid)
						if out.Err != nil || out.Person.SyncPersonKey == ""{
							log.Println(out.Err)
							log.Println("User with userid", userid, "does not exist")
							ercol = append(ercol,ErrorResultat{
								Problem:        "User does not exist",
								InfectedGroupOrPerson: userid,
							})
							continue
						}
						log.Println("Person from itslearning:", out.Person)
						profile := "Guest"
						if out.Person.Profile == "Staff"  {
							profile = "Instructor"
						}
						if out.Person.Profile == "Administrator"  {
							profile = "Administrator"
						}
						if out.Person.Profile == "Student"  {
							profile = "Learner"
						}
						resp, err := p.itsl.CreateMembership(p.GroupSyncKey, userid, profile)
						log.Println("Erstellen des Membership",p.GroupSyncKey, userid, profile)
						if err != nil {
							log.Println(out.Person.Profile)
							var tmp Envelope
							err := xml.Unmarshal([]byte(resp),&tmp)
							if err != nil {
								log.Println(err)
							}
							ercol = append(ercol,ErrorResultat{
								Problem:        tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
								InfectedGroupOrPerson: userid,
							})
						}
					*/
				} else {
					profile := ""
					if person.Profile == "Staff" {
						profile = "Instructor"
					}
					if person.Profile == "Administrator" {
						profile = "Administrator"
					}
					if person.Profile == "Student" {
						profile = "Learner"
					}

					if profile == "" {
						log.Println("Hier entsteht ein Fehler")
						ercol = append(ercol, ErrorResultat{
							Problem:               "User is not a Student, Admin or Staff",
							InfectedGroupOrPerson: userid,
						})
					}

					fmt.Println("hier", p.GroupSyncKey)
					resp, err := p.itsl.CreateMembership(p.GroupSyncKey, userid, profile)
					log.Println("member wird hinzugefügt:", p.GroupSyncKey, userid, profile)
					if err != nil {
						var tmp Envelope
						log.Println(xml.Unmarshal([]byte(resp), &tmp))
						ercol = append(ercol, ErrorResultat{
							Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
							InfectedGroupOrPerson: userid,
						})
					}
				}
			}
		}
		//Todo: Handling bei DomainGroup
		if strings.HasPrefix(p.GroupName, "Domain Users") {
			log.Println("DOMAIN GROUP CHECK!!")
			domainusers, err, resp := p.itsl.ReadMembershipsForGroup(p.GroupSyncKey)
			if err != nil {
				log.Println("Memberships auslesen von domain")
				var tmp Envelope
				log.Println(xml.Unmarshal([]byte(resp), &tmp))
				ercol = append(ercol, ErrorResultat{
					Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
					InfectedGroupOrPerson: p.GroupSyncKey,
				})
				b, err := json.Marshal(ercol)
				if err != nil {
					log.Println(err)
				}
				log.Println("Error:", string(b))
				return errors.New(string(b)), false
			}
			existingInDomainusers := make(map[string]bool)
			for _, mem := range domainusers {
				existingInDomainusers[mem.PersonID] = true
			}
			org, err, resp := p.itsl.ReadMembershipsForGroup(strconv.Itoa(int(p.OrganisationID)))
			log.Println("Memberships auslesen von Organisation")
			if err != nil {
				var tmp Envelope
				log.Println(xml.Unmarshal([]byte(resp), &tmp))
				ercol = append(ercol, ErrorResultat{
					Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
					InfectedGroupOrPerson: strconv.Itoa(int(p.OrganisationID)),
				})
				b, err := json.Marshal(ercol)
				if err != nil {
					log.Println(err)
				}
				log.Println("Error:", string(b))
				return errors.New(string(b)), false
			}
			for _, member := range org {
				if !existingInDomainusers[member.PersonID] {
					log.Println("Löschen von ", member.PersonID, "aus der Organisation, da nicht mehr in Domaingroup")
					resp, err := p.itsl.DeleteMembership(member.ID)
					if err != nil {
						var tmp Envelope
						err = xml.Unmarshal([]byte(resp), &tmp)
						if err != nil {
							log.Println(err)
						}
						ercol = append(ercol, ErrorResultat{
							Problem:               tmp.Header.SyncResponseHeaderInfo.StatusInfo.CodeMinor.CodeMinorField.CodeMinorValue + tmp.Header.SyncResponseHeaderInfo.StatusInfo.Description.Text.Text,
							InfectedGroupOrPerson: member.PersonID,
						})
					}
				}
			}
		}
	}

	b, err := json.Marshal(ercol)
	if err != nil {
		log.Println(err)
	}

	if err != nil {
		return err, false
	}

	if len(ercol) > 0 {
		log.Println("Error:", string(b))
		return errors.New(string(b)), false
	}

	return nil, false
}
