package edu.usf.cims

import groovy.sql.Sql
import groovy.io.FileType

import groovy.util.logging.Slf4j
import groovy.json.JsonOutput

import groovy.util.CliBuilder
import org.apache.commons.cli.Option

import javax.crypto.*
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec
import java.security.spec.KeySpec
import java.io.UnsupportedEncodingException
import org.apache.commons.codec.binary.Base64
import java.security.SecureRandom

@Slf4j
class GetAccounts {

    def today = new Date().format('yyyyMMdd')
    def source = 'GEMS'
    //def outdir = "/tmp/armImport-${source}-${today}"
    def outdir = "/tmp"
    def iteration = 0
    def sleeptime = 30000
    def resultSet = [:]
    def oldRoleUser=''
    def roleAccountList = []

    def file = new File("${outdir}/${source}_accounts.json")
    def file2 = new File("${outdir}/${source}_roles.json")
    def file3 = new File("${outdir}/${source}_accounts_roles.json")


public static void main(String[] args) {
  //System.out.println "Output Directory = ${outdir}"
  //new File("${outdir}").mkdirs()

  def config = new ConfigObject()
  def configFile = '/usr/local/etc/idm_config/armfeed_config.groovy'
  def defaultConfigFile = new  File(configFile)

    	if (defaultConfigFile.exists() && defaultConfigFile.canRead()) {
    		config = new ConfigSlurper().parse(new File(configFile).toURL())
    	} else {
        System.out.println "Config File Not Found: no such file ${configFile}"
    		System.exit(1)
    	}

    def sourceConnection = config.source.dbConnectString
    def sourceUser = config.source.dbUser
    def sourcePassword = config.source.dbPassword
    def sourceDriver = config.source.dbDriver
    def wsConvertURLPrefix = config.wsConvertURLPrefix
    def wsConvertURLSuffix = config.wsConvertURLSuffix

    def accountsQuery = config.accountsQuery
    def rolesQuery = config.rolesQuery
    def relDefQuery = config.relDefQuery

    try {
      def sql = Sql.newInstance( sourceConnection, sourceUser, sourcePassword, sourceDriver )

      //establish source (either GEMS or FAST)
      //setup upload environment

      sql.eachRow(relDefQuery) { roleDefRow ->
        def longDesc = ''
        if (roleDefRow.descrlong != null) longDesc = roleDefRow.descrlong.asciiStream.text

        def roleData = [
          name: roleDefRow.rolename.trim(),
          account_type: source,
          role_data: [
            short_description: roleDefRow.descr.trim(),
            long_description: longDesc
          ]
        ]

        def json = groovy.json.JsonOutput.toJson(roleData)
        file2 << groovy.json.JsonOutput.prettyPrint(json)
        file2 << "\n\n"
      }

      //getPeopleSoftAccounts3Tries

      sql.eachRow(accountsQuery) { accountsQueryRow ->

      // get Unumber from emplid
        def emplid = accountsQueryRow.emplid.trim()
      	def unumber = "U99999999"
      	if ( emplid.isNumber() ) {
      		try {
      			for (iteration=0;iteration<3;iteration++) {
      				if (unumber=="U99999999") {
      					sleep(sleeptime*iteration)
      unixtime = String.valueOf(System.currentTimeMillis() / 1000L)
      plaintext = unixtime
      encryptedToken = AESencrypt(plaintext, rcGlobals.wsConvertAESsecret)

      			def wsConvertURL = "${wsConvertURLPrefix}token=${encryptedToken}&value=$emplid&${wsConvertURLSuffix}"
      			//println wsConvertURL
      			def jsonResults = wsConvertURL.toURL().getText(connectTimeout: 120.seconds, readTimeout: 120.seconds,
      														useCaches: false, allowUserInteraction: false,
      														requestProperties: ['User-Agent': 'Groovy RuleChains Script'])
      			//println jsonResults
      			//println groovy.json.JsonOutput.prettyPrint(jsonResults)
      			def newJson = new groovy.json.JsonSlurper().parseText(jsonResults)
      					if (newJson.response=="success") {iteration+=3}
      			unumber = newJson.usfid
      		}
      	}
      		} catch (Exception e) {
      			System.out.println "unable to process ${emplid} for source ${source}"
      			System.out.println(e.toString());

      		}
      	}

      	def status = 'Active'
        if ((accountsQueryRow.operpswd =~ /.*(TERMINAT|DEPT|VOCKED).*/) || (accountsQueryRow.acctlock > 0)) status = 'Locked'
        def accountData = [
          account_type: source,
          account_identifier: accountsQueryRow.oprid.trim(),
          account_identity: unumber,
          account_data: [
            employeeID: accountsQueryRow.emplid.trim(),
            password_change: accountsQueryRow.lastpswdchange as String,
            status: status,
            last_used: accountsQueryRow.lastsignondttm as String,
            last_update: accountsQueryRow.lastupddttm as String
          ]
        ]
        resultSet+= [ account_identifier: accountsQueryRow.oprid.trim() ]
        def json = groovy.json.JsonOutput.toJson(accountData)
        file << groovy.json.JsonOutput.prettyPrint(json)
        file << "\n\n"
      }

      //getPSARoleMappings
      sql.eachRow(rolesQuery) { roleRow ->

      	if (roleRow.roleuser!='' && oldRoleUser!='' && roleRow.roleuser!=oldRoleUser) {
      		if (roleAccountList.size() >= 1) {
      			def accountRoleData = [
      				account_type: source,
      				account_identifier: oldRoleUser,
      				account_roles: roleAccountList
      			]
      			def json2 = groovy.json.JsonOutput.toJson(accountRoleData)
      			file3 << groovy.json.JsonOutput.prettyPrint(json2)
      			file3 << "\n\n"
      		}
            roleAccountList = []

      	}
      	if ((oldRoleUser=='' && roleRow.roleuser!='') || oldRoleUser!=roleRow.roleuser) {
      		oldRoleUser=roleRow.roleuser
      	}
         if (roleRow.rolename.trim() != '') {
              def dynRole = (roleRow.dynamic_sw.trim() =~ /.*Y.*/) ? true : false
              roleAccountList << [
      			href: "/roles/${source}/" + java.net.URLEncoder.encode(roleRow.rolename.trim(), "UTF-8"),
                      dynamic_role: dynRole
              ]
         }

      }
    }catch(Exception e) {
      exitOnError e.message
    }
  }

  private static exitOnError(errorString){
    System.out.println("\nERROR: ${errorString}\n")
    System.exit(1)
  }
  /*
  private static Integer.metaClass.getSeconds = { ->
  delegate * 1000
  }
*/
  private static AESencrypt = { input, key ->
    byte[] output = null
    try{

      //Create a random initialization vector
      SecureRandom random = new SecureRandom();
      byte[] randBytes = new byte[16];
      random.nextBytes(randBytes);
      IvParameterSpec iv = new IvParameterSpec(randBytes);
      SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, skey, iv);

      byte[] ivBytes = iv.getIV();
      byte[] inputBytes = input.getBytes();
      byte[] crypted = cipher.doFinal(inputBytes);

      output = new byte[ivBytes.length + crypted.length];

      System.arraycopy(ivBytes, 0, output, 0, ivBytes.length);
      System.arraycopy(crypted, 0, output, ivBytes.length, crypted.length);

    }catch(Exception e){
      System.out.println(e.toString());
    }

    return new String(Base64.encodeBase64URLSafe(output))

  } // end AESencrypt

}
