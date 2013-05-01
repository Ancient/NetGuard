/***************************************************************************
 *   NetGuard Limit Module                                                 *
 *                                                                         *
 *   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
 *                                                                         *
 *                                                                         *
 *   This program is released under a dual license.                        *
 *   GNU General Public License for open source and educational use and    *
 *   the Net-Guard Professional License for commercial use.                *
 *   Details: http://www.net-guard.net/licence                             *
 *                                                                         *
 *   For open source and educational use:                                  *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 *   For commercal use:                                                    *
 *   visit http://www.net-guard.net for details if you need a commercal    *
 *   license or not. All conditions are listed here:                       *
 *                 http://www.net-guard.net/licence                        *
 *                                                                         *
 *   If you are unsure what licence you can use you should take            *
 *   the Net-Guard Professional License.                                   *
 *                                                                         *
 ***************************************************************************/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/stat.h>
#include <time.h>

#include "compile.h"
#include "user_special_limit.hpp"
#include "../../includes/logging.h"
#include "../../includes/state/state_handling.hpp"

static const char *ACC_SPECIAL_LIMIT_VERSION_MAGIC = "netguard_special_limit_db_v0.1";

NetGuard_Special_Limit::NetGuard_Special_Limit()
{
	ng_logdebug_spam("constructor");
	general_acccounting = NULL;

	userlist = new User_Data_Tools();
	muser_data = NULL;
	my_dis_state = NULL;
	my_fail_state = NULL;

	default_limit = 7;
	default_limit = default_limit * 1024 * 1024 * 1024;

	default_daily_addition = 1;
	default_daily_addition = default_daily_addition * 1024 * 1024 * 1024;

	default_max_limit = 21;
	default_max_limit = default_max_limit * 1024 * 1024 * 1024;

	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);
	htons_ETHERTYPE_ARP = htons(ETHERTYPE_ARP);	

	required_modules.push_back("general_accounting");
}
  
NetGuard_Special_Limit::~NetGuard_Special_Limit()
{
	ng_logdebug_spam("destructor");
}

void NetGuard_Special_Limit::loaddata()
{
	struct	user_data * u_data;

	#ifdef userlist_use_simple
	struct	user_list * m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		struct user_special_accounting_data *accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_limit_module_number];
		if (accouning_data) {
			user_shutdown(u_data);
		}
		user_init(u_data);
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
}

void NetGuard_Special_Limit::savedata()
{
	struct	user_data * u_data;

	FILE *myfile;

	ng_logdebug_spam("saving users to %s",db_filename.c_str());

	myfile = fopen(db_filename.c_str(), "w+");
	if (!myfile) return;

	fwrite(ACC_SPECIAL_LIMIT_VERSION_MAGIC,strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC),1,myfile);

	struct user_special_limit_data * limit_data;

	int counter = 0;
	#ifdef userlist_use_simple
	struct	user_list * m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
		if	(limit_data) {
			counter++;
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
	//write number of users
	fwrite(&counter ,sizeof(counter),1, myfile);

	#ifdef userlist_use_simple
	m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
		if	(limit_data) {
			fwrite(&u_data->saddr ,sizeof(u_data->saddr),1, myfile);
		} else {
			ng_logerror("skipping user %-15s on saving - no data present",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}

	#ifdef userlist_use_simple
	m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
		if	(limit_data) {
			fwrite(limit_data,sizeof(struct user_special_limit_data),1, myfile);
			ng_logdebug_spam("save user %-15s max %lld",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->limit);
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
	ng_logdebug_spam("saved %d users",counter);

	fwrite(ACC_SPECIAL_LIMIT_VERSION_MAGIC,strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC),1,myfile);
	fclose(myfile);
}

struct user_special_limit_data * NetGuard_Special_Limit::load_limit_data(struct user_data *u_data, char *filename, int rename_onfail){
	FILE *myfile;
	struct stat fileinfo;
	char *tmpdata;
	struct user_special_limit_data * limit_data = NULL;
	int i;
	off_t f_pos;

	ng_logdebug_spam("loading data from %s",db_filename.c_str());

	if (stat(db_filename.c_str(),&fileinfo)) {
		ng_logerror("cant stat data file %s",db_filename.c_str());
		return NULL;
	}
	myfile = fopen(db_filename.c_str(), "r");
	if (!myfile) {
		ng_logerror("cant open data file %s",db_filename.c_str());
		return NULL;
	}
	
	//check file version
	tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC)+1));
	tmpdata[strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC)] = 0;
	int count = fread(&tmpdata[0],strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_SPECIAL_LIMIT_VERSION_MAGIC) ) {
		ng_logerror("limit: cant read traffic data from %s - illegal format (%s <> %s)",db_filename.c_str(),(char *)tmpdata,ACC_SPECIAL_LIMIT_VERSION_MAGIC);

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(db_filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",db_filename.c_str(),(int)now);
			ng_log("renaming file to %s",tmpdata);
			rename(db_filename.c_str(),tmpdata);
		}
		return NULL;
	}

	f_pos = ftell(myfile);
	fseek(myfile,fileinfo.st_size-strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC),SEEK_SET);
	count = fread(&tmpdata[0],strlen(ACC_SPECIAL_LIMIT_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_SPECIAL_LIMIT_VERSION_MAGIC) ) {
		ng_logerror("cant read traffic data from %s - illegal (end) format (%s <> %s)",db_filename.c_str(),(char *)tmpdata,ACC_SPECIAL_LIMIT_VERSION_MAGIC);

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(db_filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",db_filename.c_str(),(int)now);
			ng_log("renaming file to %s",tmpdata);
			rename(db_filename.c_str(),tmpdata);
		}
		return NULL;
	}
	//set to old position again
	fseek(myfile,f_pos,SEEK_SET);

	ng_logdebug_spam("loading %lu bytes data",fileinfo.st_size);

	int counter = 0;
	count = fread(&counter,sizeof(counter),1, myfile);
	if (count  != 1 ) return NULL;
	ng_logdebug_spam("found %d users in file",counter);

	u_int32_t saddr;
	int found = 0;
	unsigned int seek_pos = 0;
	for (i=1; i<=counter ; i++ )
	{
		count = fread(&saddr ,sizeof(saddr),1, myfile);
		if (count  != 1 ) return NULL;
		if (saddr == u_data->saddr)
		{
			found = 1;
			seek_pos = i;
			ng_logdebug_spam("found user %-15s on pos %d",inet_ntoa(*(struct in_addr *)&u_data->saddr),seek_pos);
		}
	}

	if (!found) return NULL;
	seek_pos = (seek_pos-1) * sizeof(struct user_special_limit_data) + ftell(myfile);
	fseek(myfile,seek_pos,SEEK_SET);


	limit_data = (struct user_special_limit_data *)malloc(sizeof(struct user_special_limit_data));
	count = fread(limit_data,sizeof(struct user_special_limit_data),1, myfile);
	if (count  != 1 ) {
		delete limit_data;
		return NULL;
	}
	ng_logdebug_spam("loaded user data for %-15s (max: %lld) ",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->limit);

	fclose(myfile);
	free(tmpdata);

	return limit_data;
}

int NetGuard_Special_Limit::init(NetGuard_Config *data)
{
	general_acccounting = NULL;
	muser_data = NULL;

	ng_logdebug_spam("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetStr("user_special_limit_filename") == "")
	{
		ng_logerror("need a user_special_limit_filename in config data");
		return -2;
	}
	db_filename=data_->GetStr("user_special_limit_filename");

	if (data_->GetModule("module_general_accounting") == NULL) {
		ng_logerror("need general_accounting module needs to be loaded");
		return -2;
	}


	//filter for accountable traffic
	if (data_->GetStr("accounting_filter_own") == "")
	{
		ng_logerror("need an accounting_filter_own in config data");
		return -2;
	}
	std::string filter_name_own=data_->GetStr("accounting_filter_own");

	filter_own = NetGuard_Global_IP_Filter::Filter(filter_name_own);
	if (filter_own == NULL)
	{
		ng_logerror("filter passed with accounting_filter_own (%s) does not exists",filter_name_own.c_str());
		return -2;
	}
	ng_logdebug_spam("using filter (%s) for filtering accounting ips",filter_own->GetPrefixName().c_str());

	//filter for internal traffic
	if (data_->GetStr("accounting_filter_intern") == "")
	{
		ng_logerror("need an accounting_filter_intern in config data");
		return -2;
	}
	std::string filter_name_intern=data_->GetStr("accounting_filter_intern");

	filter_intern = NetGuard_Global_IP_Filter::Filter(filter_name_intern);
	if (filter_intern == NULL)
	{
		ng_logerror("filter passed with accounting_filter_intern (%s) does not exists",filter_name_intern.c_str());
		return -2;
	}
	ng_logdebug_spam("using filter (%s) for filtering internal traffic",filter_intern->GetPrefixName().c_str());


	if (data_->GetInt("default_limit") != MININT)
	{
		default_limit = data_->GetInt("default_limit");
		default_limit = default_limit*1024*1024;
		ng_logdebug("set default_limit to %llu",default_limit);
	}

	if (data_->GetInt("default_max_limit") != MININT)
	{
		default_max_limit = data_->GetInt("default_max_limit");
		default_max_limit = default_max_limit*1024*1024;
		ng_logdebug("set default_max_limit to %llu",default_max_limit);
	}

	if (data_->GetInt("default_daily_addition") != MININT)
	{
		default_daily_addition = data_->GetInt("default_daily_addition");
		default_daily_addition = default_daily_addition*1024*1024;
		ng_logdebug("set default_daily_addition to %llu",default_daily_addition);
	}

	general_acccounting = (NetGuard_General_Module*)data_->GetModule("module_general_accounting");
	muser_data = (User_Data_Tools*)general_acccounting->get_data(NULL);

	my_dis_state = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("user_special_limit.disable_state","disabled"));
	if (!my_dis_state) {
		ng_logerror("%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("user_special_limit.disable_state","disabled").c_str());
		return -2;
	}

	my_fail_state = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("user_special_limit.failure_state","failure"));
	if (!my_fail_state) {
		ng_logerror("%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("user_special_limit.failure_state","failure").c_str());
		return -2;
	}

	loaddata();

	return 0;
}

void NetGuard_Special_Limit::shutdown()
{
	ng_logdebug_spam("shutdown");
	if (muser_data)
	{
		struct	user_data *u_data;
		#ifdef userlist_use_simple
		struct	user_list *m_users = muser_data->get_list();
		while (m_users != NULL) {
			u_data = m_users->data;
		#else
		ip_storage_hash::iterator it;
		for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
			u_data =  (*it).second;
		#endif
			user_shutdown(u_data);
			#ifdef userlist_use_simple
			m_users = m_users->next;
			#endif
		}
	}

	general_acccounting = NULL;
	muser_data = NULL;
}

struct user_special_limit_data *NetGuard_Special_Limit::my_user_init(struct user_data *u_data, bool doload)
{
	struct user_special_limit_data * limit_data = NULL;
	
	//try to load it from file
	if (doload)
		limit_data = load_limit_data(u_data,NULL,1);

	if (limit_data == NULL)
	{
		ng_logdebug("setting new default special limits for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		//we need to init a new user
		//we need to init a new user
		limit_data = (struct user_special_limit_data *)malloc(sizeof(struct user_special_limit_data));

		//set default values
		memset(limit_data,0,sizeof(struct user_special_limit_data));
		limit_data->limit = (long long int)default_limit;
		limit_data->daily_addition = (unsigned long long int)default_daily_addition;
		limit_data->max_limit = (unsigned long long int)default_max_limit;
		u_data->external.bytes = limit_data->limit;
	};

	u_data->module_data[user_special_limit_module_number] = limit_data;

	return limit_data;	
}

void NetGuard_Special_Limit::user_init(struct user_data *u_data)
{
	if (!u_data) return;
	ng_logdebug_spam("user_init for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	my_user_init(u_data,true);
}

void NetGuard_Special_Limit::user_shutdown(struct user_data *u_data)
{
	struct user_special_limit_data * limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
	if ( limit_data != NULL ) {		
		ng_logdebug_spam("free limits data for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		delete limit_data;
	}
	u_data->module_data[user_special_limit_module_number] = NULL;
}


void NetGuard_Special_Limit::do_user_data_forgetday(int day, struct user_data *u_data){

	struct user_special_limit_data *limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
	if ( limit_data == NULL ) {
		limit_data = my_user_init(u_data,true);
	}
	
	if((u_data->external.bytes + limit_data->daily_addition) > limit_data->max_limit)
		 u_data->external.bytes = limit_data->max_limit;
	else
		 u_data->external.bytes += limit_data->daily_addition;

}

void NetGuard_Special_Limit::user_data_forgetday(int day)
{
	struct	user_data *u_data;

	#ifdef userlist_use_simple
	struct	user_list *m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif

		//forget this day for external traffic
		do_user_data_forgetday(day,u_data);

		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
}

void NetGuard_Special_Limit::checkmax(struct user_special_limit_data * limit_data,struct user_data *u_data) {

	if(limit_data->limit > 0)
	{
		if(u_data->external.bytes <= 0)
		{
			// we have somebody over the internal over all limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			//nu_state->params()->SetInt("external_limit_exceeded",nu_state->params()->GetInt("external_limit_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_int_state_overall_msg","user have no traffic left"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}
}

void NetGuard_Special_Limit::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	in_addr_t *index_addr;
	in_addr_t *index_addr2;
	index_addr = 0;
	index_addr2 = 0;

	//we are only interested in packages that are linked to a user already	
	if (!u_data) return;

	struct user_special_limit_data *limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
	if ( limit_data == NULL ) {
		limit_data = my_user_init(u_data,true);
	}

	if (eth->ether_type == htons_ETHERTYPE_IP) {
		hl_saddr = ntohl(ip->saddr);
		hl_daddr = ntohl(ip->daddr);
		if ((*filter_own)==&hl_saddr) index_addr = &ip->saddr;
		if ((*filter_own)==&hl_daddr) index_addr2 = &ip->daddr;
	} else if (eth->ether_type == htons_ETHERTYPE_ARP) {
		struct ether_arp * arph;
		//#if __GNUC__ >= 4
		arph = (struct ether_arp *)ip;
		//#else
		//(void *)arph = (void *)ip;
		//#endif		
		hl_saddr = ntohl(*(uint32_t *)&arph->arp_spa);
		hl_daddr = ntohl(*(uint32_t *)&arph->arp_tpa);
		if ((*filter_own)==&hl_saddr) index_addr = (uint32_t *)&arph->arp_spa;
		if ((*filter_own)==&hl_daddr) index_addr2 = (uint32_t *)&arph->arp_tpa;
	}

	

	struct user_data_traffic *traffic_type;
	
	//set if internal or external traffic
	//default is internal for all non ip protocols


	if (eth->ether_type == htons_ETHERTYPE_IP) {
		//on ip its external per default
		traffic_type = &u_data->external;

		//if it match the filters its internal -> return
		if ((*filter_intern) == &hl_daddr && (*filter_intern)==&hl_saddr) return;
	}else
		return;

	signed long long int tmpval;
	tmpval = traffic_type->bytes;

	if((tmpval - h->tp_len) >= 0)
		traffic_type->bytes = traffic_type->bytes - h->tp_len;
	else 
		traffic_type->bytes = 0;

	checkmax(limit_data,u_data);
}

void NetGuard_Special_Limit::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_logout("save - save limit data");
		ng_logout("dumpip <ip> <vlan> - show details for an ip");
		ng_logout("dumpip_all <ip> <vlan> - show details for an ip");
		ng_logout("set_limit <ip> <vlan> <start limit MB> <daily add MB> <maximum MB> - set limit data for an ip");
		//TODO: ng_logout("set_limit_reset <ip> <vlan> - set limit data for an ip to default"); 
		ng_logout("set_current_traffic <ip> <vlan> <traffic MB> - set the current traffic volume for an ip");
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "save")
	{
		savedata();
	}

	if ((params[0] == "dumpip") ||  (params[0] == "dumpip_all"))
	{
		if (params.size() != 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}
		

		#define EINHEIT 1024/1024
		struct user_special_limit_data *limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
		if ( limit_data == NULL ) {
			limit_data = my_user_init(u_data,true);
		}

		ng_logout("start limit \t\t: %llu MByte",limit_data->limit/EINHEIT);
		ng_logout("daily addition \t\t: %llu MByte",limit_data->daily_addition/EINHEIT);
		ng_logout("max limit \t\t: %llu MByte",limit_data->max_limit/EINHEIT);

		ng_logout("current usage \t\t: %llu MByte",u_data->external.bytes/EINHEIT);
	}

	if ((params[0] == "set_limit"))
	{
		if (params.size() != 6)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <start limit MB> <daily add MB> <maximum MB>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <start limit MB> <daily add MB> <maximum MB>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <start limit MB> <daily add MB> <maximum MB>",params[0].c_str());
			return;
		}

		if (intparams[3]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <start limit MB> <daily add MB> <maximum MB>",params[0].c_str());
			return;
		}

		if (intparams[4]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <start limit MB> <daily add MB> <maximum MB>",params[0].c_str());
			return;
		}

		if (intparams[5]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <start limit MB> <daily add MB> <maximum MB>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}

		struct user_special_limit_data *special_limit_data = (struct user_special_limit_data *)u_data->module_data[user_special_limit_module_number];
		if ( special_limit_data == NULL ) {
			special_limit_data = my_user_init(u_data,true);
		}

		#define EINHEIT2 1024*1024

		unsigned long long int tmpval,tmpval2,tmpval3;
		tmpval = (unsigned long long int)intparams[3] * (unsigned long long int)EINHEIT2;
		tmpval2 = (unsigned long long int)intparams[4] * (unsigned long long int)EINHEIT2;
		tmpval3 = (unsigned long long int)intparams[5] * (unsigned long long int)EINHEIT2;

		ng_logout_ok("setting new special limit data");
		special_limit_data->limit = tmpval;
		special_limit_data->daily_addition = tmpval2;
		special_limit_data->max_limit = tmpval3;

	}

	if ((params[0] == "set_current_traffic"))
	{
		if (params.size() != 4)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <traffic MB>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <traffic MB>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <traffic MB>",params[0].c_str());
			return;
		}

		if (intparams[3]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <traffic MB>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}

		#define EINHEIT 1024/1024
		#define EINHEIT2 1024*1024

		unsigned long long int tmpval;

		tmpval = (unsigned long long int)intparams[3] * (unsigned long long int)EINHEIT2;

		u_data->external.bytes = tmpval;
		ng_logout_ok("new traffic successfully set to: %llu MB",u_data->external.bytes/EINHEIT);
	}
}

void NetGuard_Special_Limit::timer_tick() {
}
