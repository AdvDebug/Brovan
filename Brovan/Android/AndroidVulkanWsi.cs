using System;
using System.Runtime.InteropServices;

namespace Brovan.Android
{
    internal static class AndroidVulkanWsi
    {
        internal const int VkStructureTypeAndroidSurfaceCreateInfoKHR = 1000008000;

        [DllImport("vulkan-1.dll", EntryPoint = "vkCreateAndroidSurfaceKHR", CallingConvention = CallingConvention.Winapi)]
        internal static extern int vkCreateAndroidSurfaceKHR(IntPtr instance, IntPtr pCreateInfo, IntPtr pAllocator, IntPtr pSurface);
    }
}
