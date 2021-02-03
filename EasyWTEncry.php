<?php
namespace xxxxx;

/* 字符串加/解密机制 
** create ：王智鹏（WAM）
*/
class EasyWTEncry
{
	
	/* 加密密钥 */
	private $secret_key;

	/* IP验证 */
	private $ipverify;

	public function __construct (String $secret_key='', String $ipverify='') 
	{
		$this->secret_key  = $secret_key;
		$this->ipverify    = $ipverify;
	}
	
	/* 获取secrt_key的固定值 */
	private function secret_solidify_val (String $secret_key) 
	{
		
		$secret_md5     = MD5($secret_key);
		
		$secret_md5_len = strlen($secret_md5);

		$secret_crc32   = crc32($secret_md5);
		
		$fixed_num = 0;

		for ($i = 0; $i < $secret_md5_len; $i++)
		{
			$fixed_num += $secret_crc32 % ord($secret_md5[$i]);
		}

		$decimal = 2;

		$cardinal_number = $secret_crc32 / $fixed_num / pi();

		$cardinal_number -= floor($cardinal_number);

		$result = 0;

		for ($i = 1; $i <= $decimal; $i++)
		{

			$cloth = pow(10, $i);

			$result += floor($cardinal_number * $cloth);
			
			if ($i == $decimal && $result == 0) {
				
				$cardinal_number *= $cloth;

				$i = 1;

			}

		}
		
		return $result;

	}

	/* 加密 */
	public function encryption ($data, Int $expire=0, String $secret_key='') 
	{
		
		if (empty($data)) 
		{
			return false;
		}
		
		/* 验证数字 */
		if (!is_integer($expire)) 
		{
			return false;
		} 
		else if ($expire > 0) 
		{
			$expire = time()+$expire;
		}
		
		$ip = $this->ipverify?:'';
		
		$secret_key = !empty($secret_key)?$secret_key:$this->secret_key;
		
		$encry_result = base64_encode($this->encryption_operation($data, $ip, $expire, $secret_key));
		
		$encry_result_len = ceil(strlen($encry_result) / $this->secret_solidify_val($secret_key));
		
		$encry_result_substr = substr($encry_result, $encry_result_len).substr($encry_result, 0, $encry_result_len);
		
		return strrev($encry_result_substr);
	}
	
	/* 加密机制 */
	private function encryption_operation ($data, String $ip, Int $expire, String $secret_key) 
	{
		
		$secret_key_tmp = $secret_key;

		$json_string = json_encode($data)?:$data;
		
		$json_string_64 = base64_encode($json_string);
		
		$secret_key_64 = $this->_MD5($secret_key_tmp.$ip);
		
		$len1 = strlen($secret_key_64);
		$len2 = strlen($json_string_64);
		
		$random = ord($secret_key_64[rand(1, $len1-1)]);
		
		for ($i = 0; $i < $len2; $i++) 
		{
			$ord = ord($json_string_64[$i])+$random;
			$json_string_64[$i] = chr($ord);
		}
		
		$json_string_64 = base64_encode(chr($random+ord($secret_key_64[$len1/2])).$json_string_64);
		
		$encry_str = base64_encode($json_string_64.$secret_key_64);
		$encry_str_total = strlen($encry_str);
		
		$random = rand(1, $encry_str_total);
		
		$encry_str2 = '';
		for ($i = 0; $i < $encry_str_total; $i++) 
		{
			$ord = ord($encry_str[$i])+$random;
			$encry_str2 .= chr($ord);
		}
		
		$encry_str2 = base64_encode($encry_str2);
		
		$encry_total = $random+$encry_str_total.'';
		$encry_total_len = strlen($encry_total);
		
		$encry_total_str = '';
		for ($i = 0; $i < $encry_total_len; $i++) 
		{
			$encry_total_str .= $encry_total[$encry_total_len-($i+1)].$encry_str2[$encry_total[$i]];
		}
		$encry_total_str = base64_encode($encry_total_str.chr($encry_str_total+$encry_total));
		
		return $encry_total_str.'.'.$encry_str2.'.'.$this->_MD5($encry_total_str.$this->secret_solidify_val($secret_key_tmp).$encry_str2.$expire).'.'.$expire;
	}
	
	/* 解密 */
	public function decryption (String $string, String $secret_key='') 
	{
		
		$string = strrev($string);

		$secret_key = !empty($secret_key)?$secret_key:$this->secret_key;
		
		$string_len = strlen($string)-ceil(strlen($string) / $this->secret_solidify_val($secret_key));
		
		$encry_result = base64_decode(substr($string, $string_len).substr($string, 0, $string_len));
		
		$ip = $this->ipverify?:'';
		
		return $this->decryption_operation($encry_result, $ip, $secret_key);
	}
	
	/* 解密机制 */
	private function decryption_operation (String $string, String $ip, String $secret_key) 
	{

		$secret_key_tmp = $secret_key;
		
		$secret_key_64 = $this->_MD5($secret_key_tmp.$ip);
		
		$encry_arr = explode('.', $string);
		
		if (count($encry_arr) !== 4) 
		{
			return false;
		}
		
		$encry_total_str = $encry_arr[0];
		$encry_str2      = $encry_arr[1];
		$md5             = $encry_arr[2];
		$expire          = $encry_arr[3];
		
		/* 验证数据一致性 */
		if ($this->_MD5($encry_total_str.$this->secret_solidify_val($secret_key_tmp).$encry_str2.$expire) !== $md5) 
		{
			return false;
		}
		
		if ($expire != 0 && time() > $expire) 
		{
			return false;
		}
		
		$encry_total2 = base64_decode($encry_total_str);
		
		$encry_total_ord = ord(substr($encry_total2,-1));
		
		$encry_total_str = substr($encry_total2,0, -1);
		
		$encry_total = '';
		for ($i = 0; $i < strlen($encry_total_str); $i++) 
		{
			if ($i % 2 == 0) 
			{
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
		for ($i = 0; $i < $encry_str2_len; $i++) 
		{
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
		
		for ($i = 0; $i < $len2; $i++) 
		{
			$ord = ord($sources_real_data[$i])-$random;
			$sources_real_data[$i] = chr($ord);
		}
		
		//判断是否与密钥一致
		if ($secret_key_64 !== $secret_key_64_tmp) 
		{
			return false;
		}
		
		$sources_data = base64_decode($sources_real_data);
		
		$sources = json_decode($sources_data, true)?:$sources_data;
		
		return $sources;
	}

	/* 更新加密字符串有效期 */
	public function update_expire ($string, String $expire_date) 
	{
		
		$string = strrev($string);

		$secret_key = !empty($secret_key)?$secret_key:$this->secret_key;
		
		$string_len = strlen($string)-floor(strlen($string) / $this->secret_solidify_val($secret_key));
		
		$encry_result = base64_decode(substr($string, $string_len).substr($string, 0, $string_len));
		
		$ip = $this->ipverify?:'';
		
		$encry_result = base64_encode($this->update_expire_operator($encry_result, $ip, $secret_key, strtotime($expire_date)));

		$encry_result_len = floor(strlen($encry_result) / $this->secret_solidify_val($secret_key));
		
		$encry_result_substr = substr($encry_result, $encry_result_len).substr($encry_result, 0, $encry_result_len);
		
		return strrev($encry_result_substr);

	}

	/* 加密字符串验证并更新有效期 */
	private function update_expire_operator (String $string, String $ip, String $secret_key, Int $new_expire) 
	{

		$secret_key_64 = $this->_MD5($secret_key.$ip);
		
		$encry_arr = explode('.', $string);
		
		if (count($encry_arr) !== 4) 
		{
			return false;
		}
		
		/* 验证数据一致性 */
		if ($this->_MD5($encry_arr[0].$this->secret_solidify_val($secret_key).$encry_arr[1].$encry_arr[3]) !== $encry_arr[2]) 
		{
			return false;
		}
		
		if ($encry_arr[3] != 0 && time() > $encry_arr[3]) 
		{
			return false;
		}

		$encry_arr[2] = $this->_MD5($encry_arr[0].$this->secret_solidify_val($secret_key).$encry_arr[1].$new_expire);
		$encry_arr[3] = $new_expire;

		return implode('.', $encry_arr);
		
	}
	
	private function _MD5 ($val, $flag=true) 
	{
		if ($flag === true) 
		{
			return substr(MD5($val), 8, 16);
		} 
		else 
		{
			return MD5($val);
		}
	}
}
