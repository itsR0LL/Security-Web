const countryDisplayNames: Record<string, string> = {
  CN: "中国大陆",
  US: "美国",
  JP: "日本",
  IN: "印度",
  DE: "德国",
  FR: "法国",
  SG: "新加坡",
  CH: "瑞士",
  ES: "西班牙",
  GB: "英国",
  KR: "韩国",
  NL: "荷兰",
  RU: "俄罗斯",
  SE: "瑞典",
  BR: "巴西",
  HK: "中国香港",
  TW: "中国台湾",
  CA: "加拿大",
  AU: "澳大利亚",
  IT: "意大利",
  China: "中国大陆",
  "Mainland China": "中国大陆",
  "Chinese Mainland": "中国大陆",
  "United States": "美国",
  "United States of America": "美国",
  USA: "美国",
  Japan: "日本",
  India: "印度",
  Germany: "德国",
  France: "法国",
  Singapore: "新加坡",
  Switzerland: "瑞士",
  Spain: "西班牙",
  "United Kingdom": "英国",
  Britain: "英国",
  Korea: "韩国",
  "South Korea": "韩国",
  Netherlands: "荷兰",
  Russia: "俄罗斯",
  Sweden: "瑞典",
  Brazil: "巴西",
  "Hong Kong": "中国香港",
  Taiwan: "中国台湾",
  Canada: "加拿大",
  Australia: "澳大利亚",
  Italy: "意大利",
  中国大陆: "中国大陆",
  中国: "中国",
  美国: "美国",
  日本: "日本",
  德国: "德国",
  新加坡: "新加坡",
  印度: "印度",
  法国: "法国",
  瑞士: "瑞士",
  西班牙: "西班牙",
  英国: "英国",
  韩国: "韩国",
  荷兰: "荷兰",
  俄罗斯: "俄罗斯",
  瑞典: "瑞典",
  巴西: "巴西",
  中国香港: "中国香港",
  中国台湾: "中国台湾",
  加拿大: "加拿大",
  澳大利亚: "澳大利亚",
  意大利: "意大利",
};

export function localizeCountryName(value: string | null | undefined) {
  if (!value) return "";
  const normalized = value.trim();
  if (!normalized) return "";
  const countryCode = normalized.length === 2 ? normalized.toUpperCase() : normalized;
  return countryDisplayNames[normalized] ?? countryDisplayNames[countryCode] ?? normalized;
}

export function hasCountryDisplayName(value: string | null | undefined) {
  if (!value) return false;
  const normalized = value.trim();
  if (!normalized) return false;
  const countryCode = normalized.length === 2 ? normalized.toUpperCase() : normalized;
  return Boolean(countryDisplayNames[normalized] ?? countryDisplayNames[countryCode]);
}

export function formatCountryDisplayName(value: string | null | undefined) {
  if (!value) return "";
  const normalized = value.trim();
  if (!normalized) return "";
  const localized = localizeCountryName(value);
  return localized === normalized ? normalized : `${localized} (${normalized})`;
}
