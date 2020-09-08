<?php
namespace xxxx;

/* 字符串加/解密机制 
** create ：王智鹏（WAM）
*/
class EasyWTEncry
{
	
	/* 加密密钥 */
	private $secret_key = '';

	private $ipverify = true;
	
	public function __construct ($secret_key='', $ipverify=true) {
		$this->secret_key = $secret_key;
		$this->ipverify   = $ipverify;
	}
	
	/* 加密 */
	public function encryption ($data, $expire=0, $secret_key='') {

		if (empty($data)) {
			return false;
		}
		
		/* 验证数字 */
		if (!is_integer($expire)) {
			return false;
		} else if ($expire > 0) {
			$expire = time()+$expire;
		}

		$ip = $this->ipverify?$_SERVER['REMOTE_ADDR']:'';
		
		$encry_result = base64_encode($this->encryption_operation($data, $ip, $expire, $secret_key));
		
		$encry_result_len = strlen($encry_result)/2;
		
		$encry_result_substr = substr($encry_result, $encry_result_len).substr($encry_result, 0, $encry_result_len);
		
		return strrev($encry_result_substr);
	}
	
	/* 加密机制 */
	private function encryption_operation ($data, $ip, $expire, $secret_key) {
		
		$secret_key_tmp = !empty($secret_key)?$secret_key:$this->secret_key;

		$json_string = json_encode($data)?:$data;
		
		$json_string_64 = base64_encode($json_string);
		
		$secret_key_64 = $this->_MD5($secret_key_tmp.$ip);
		
		$len1 = strlen($secret_key_64);
		$len2 = strlen($json_string_64);
		
		$random = ord($secret_key_64[rand(1, $len1-1)]);
		
		for ($i = 0; $i < $len2; $i++) {
			$ord = ord($json_string_64[$i])+$random;
			$json_string_64[$i] = chr($ord);
		}
		
		$json_string_64 = base64_encode(chr($random+ord($secret_key_64[$len1/2])).$json_string_64);
		
		$encry_str = base64_encode($json_string_64.$secret_key_64);
		$encry_str_total = strlen($encry_str);
		
		$random = rand(1, $encry_str_total);
		
		$encry_str2 = '';
		for ($i = 0; $i < $encry_str_total; $i++) {
			$ord = ord($encry_str[$i])+$random;
			$encry_str2 .= chr($ord);
		}
		
		$encry_str2 = base64_encode($encry_str2);
		
		$encry_total = $random+$encry_str_total.'';
		$encry_total_len = strlen($encry_total);
		
		$encry_total_str = '';
		for ($i = 0; $i < $encry_total_len; $i++) {
			$encry_total_str .= $encry_total[$encry_total_len-($i+1)].$encry_str2[$encry_total[$i]];
		}
		$encry_total_str = base64_encode($encry_total_str.chr($encry_str_total+$encry_total));
		
		return $encry_total_str.'.'.$encry_str2.'.'.$this->_MD5($encry_total_str.$encry_str2.$expire).'.'.$expire;
	}
	
	/* 解密 */
	public function decryption ($string, $secret_key='') {
		
		$string = strrev($string);
		
		$string_len = strlen($string)/2;
		
		$encry_result = base64_decode(substr($string, $string_len).substr($string, 0, $string_len));
		
		$ip = $this->ipverify?$_SERVER['REMOTE_ADDR']:'';

		return $this->decryption_operation($encry_result, $ip, $secret_key);
	}
	
	/* 解密机制 */
	private function decryption_operation ($string, $ip, $secret_key) {

		$secret_key_tmp = !empty($secret_key)?$secret_key:$this->secret_key;
		
		$secret_key_64 = $this->_MD5($secret_key_tmp.$ip);
		
		$encry_arr = explode('.', $string);

		if (count($encry_arr) !== 4) {
			return false;
		}
		
		$encry_total_str = $encry_arr[0];
		$encry_str2      = $encry_arr[1];
		$md5             = $encry_arr[2];
		$expire          = $encry_arr[3];
		
		if ($expire != 0 && time() > $expire) {
			return false;
		}
		
		/* 验证数据一致性 */
		if ($this->_MD5($encry_total_str.$encry_str2.$expire) !== $md5) {
			return false;
		}
		
		$encry_total2 = base64_decode($encry_total_str);
		
		$encry_total_ord = ord(substr($encry_total2,-1));
		
		$encry_total_str = substr($encry_total2,0, -1);
		
		$encry_total = '';
		for ($i = 0; $i < strlen($encry_total_str); $i++) {
			if ($i % 2 == 0) {
				$encry_total .= $encry_total_str[$i];
			}
		}
		
		//获取加密的随机值及内容加密的总长度
		$encry_total = strrev($encry_total);
		$encry_str_total = $encry_total_ord - $encry_total;
		$random = $encry_total - $encry_str_total;
		
		$encry_str2 = base64_decode($encry_str2);
		$encry_str2_len = strlen($encry_str2);
		
		$encry_str = '';
		for ($i = 0; $i < $encry_str2_len; $i++) {
			$ord = ord($encry_str2[$i])-$random;
			$encry_str .= chr($ord);
		}
		
		$sources_64 = base64_decode($encry_str);
		$secret_key_64_len = strlen($secret_key_64);
		$secret_key_64_tmp = substr($sources_64, -($secret_key_64_len));
		$sources_data_64 = base64_decode(substr($sources_64, 0, (strlen($sources_64)-$secret_key_64_len)));
		
		$sources_real_data = substr($sources_data_64, 1);
		
		$len1 = strlen($secret_key_64);
		$len2 = strlen($sources_real_data);
		
		$random = ord($sources_data_64[0]) - ord($secret_key_64[$len1/2]);
		
		for ($i = 0; $i < $len2; $i++) {
			$ord = ord($sources_real_data[$i])-$random;
			$sources_real_data[$i] = chr($ord);
		}
		
		//判断是否与密钥一致
		if ($secret_key_64 !== $secret_key_64_tmp) {
			return false;
		}
		
		$sources_data = base64_decode($sources_real_data);
		
		$sources = json_decode($sources_data, true)?:$sources_data;
		
		return $sources;
	}
	
	private function _MD5 ($val, $flag=true) {
		if ($flag === true) {
			return substr(MD5($val), 8, 16);
		} else {
			return MD5($val);
		}
	}
}
