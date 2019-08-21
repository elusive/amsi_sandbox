namespace AmsiSandbox.GroupPolicyCom
{
    public class GroupPolicyObjectSettings
    {
        private const uint registryFlag = 0x00000001;
        private const uint readonlyFlag = 0x00000002;
        public readonly bool LoadRegistryInformation;
        public readonly bool Readonly;

        public GroupPolicyObjectSettings(bool loadRegistryInfo = true, bool readOnly = false)
        {
            LoadRegistryInformation = loadRegistryInfo;
            Readonly = readOnly;
        }

        internal uint Flag
        {
            get
            {
                uint flag = 0x00000000;
                if (LoadRegistryInformation)
                    flag |= registryFlag;
                if (Readonly)
                    flag |= readonlyFlag;
                return flag;
            }
        }
    }
}